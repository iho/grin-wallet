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

//! End-to-end multisig transaction construction (local / in-process quorum).
//!
//! Builds a complete Grin [`Transaction`] where:
//! - output rangeproofs are multiparty Bulletproofs
//! - the kernel excess is signed with multiparty threshold aggsig
//! - the kernel offset is deterministic from the view seed + session context
//!
//! This path assumes the full quorum is available in-process (same as
//! `run_rangeproof_local` / `run_kernel_sign_local`). Networked multiparty
//! uses the same primitives via slatepack messages.
//!
//! **Does not** consult the chain or wallet UTXO set — callers supply coin
//! identities. Suitable for crypto validation and local-sim demos.

use crate::grin_core::core::hash::Hashed;
use crate::grin_core::core::transaction::{
	Input, Inputs, Output, OutputFeatures, Transaction, TxKernel, Weighting,
};
use crate::grin_core::ser;
use crate::grin_keychain::BlindingFactor;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Secp256k1;
use crate::grin_util::{from_hex, ToHex};
use crate::Error;

use super::coin::CoinId;
use super::kernel::{excess_commitment, run_kernel_sign_local};
use super::poly::PublicPoly;
use super::rangeproof::run_rangeproof_local;
use super::share::{canonical_quorum, ActorPoint};
use super::types::MultisigWalletState;

/// A fully constructed multisig UTXO (commit + rangeproof).
#[derive(Clone, Debug)]
pub struct MultisigOutput {
	/// Coin identity used for key derivation.
	pub coin: CoinId,
	/// Pedersen commitment.
	pub commit: Commitment,
	/// Multiparty rangeproof.
	pub proof: RangeProof,
}

/// Result of a local-sim spend.
#[derive(Clone, Debug)]
pub struct MultisigSpendResult {
	/// Built transaction (ready for `validate`).
	pub tx: Transaction,
	/// Newly created outputs (for chaining further spends).
	pub outputs: Vec<MultisigOutput>,
	/// Kernel excess commitment.
	pub excess: Commitment,
	/// Session id used for signing.
	pub session_id: Vec<u8>,
}

/// Create one multisig output with a multiparty rangeproof.
pub fn create_multisig_output(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	coin: &CoinId,
) -> Result<MultisigOutput, Error> {
	let (proof, params) = run_rangeproof_local(secp, public_poly, quorum, coin, None)?;
	Ok(MultisigOutput {
		coin: coin.clone(),
		commit: params.commit,
		proof,
	})
}

/// Build a complete spend: inputs → outputs + fee, multiparty RP + kernel.
///
/// Value check: `sum(input.values) == sum(output.values) + fee`.
pub fn build_multisig_spend(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	inputs: &[MultisigOutput],
	output_coins: &[CoinId],
	fee: u64,
	session_id: impl AsRef<[u8]>,
) -> Result<MultisigSpendResult, Error> {
	if inputs.is_empty() {
		return Err(Error::Multisig("spend requires at least one input".into()));
	}
	if output_coins.is_empty() {
		return Err(Error::Multisig("spend requires at least one output".into()));
	}

	let in_sum: u64 = inputs.iter().map(|o| o.coin.value).sum();
	let out_sum: u64 = output_coins.iter().map(|c| c.value).sum();
	if in_sum != out_sum.saturating_add(fee) {
		return Err(Error::Multisig(format!(
			"value imbalance: inputs {} != outputs {} + fee {}",
			in_sum, out_sum, fee
		)));
	}

	// Multiparty rangeproofs for each new output
	let mut new_outputs = Vec::with_capacity(output_coins.len());
	for coin in output_coins {
		new_outputs.push(create_multisig_output(secp, public_poly, quorum, coin)?);
	}

	// Multiparty kernel
	let in_ids: Vec<CoinId> = inputs.iter().map(|o| o.coin.clone()).collect();
	let out_ids: Vec<CoinId> = output_coins.to_vec();
	let (sig, agg, session) = run_kernel_sign_local(
		secp,
		public_poly,
		quorum,
		session_id.as_ref(),
		fee,
		in_ids,
		out_ids,
	)?;

	let excess = excess_commitment(secp, &agg)?;
	let kernel = TxKernel {
		features: session.features.clone(),
		excess,
		excess_sig: sig,
	};
	// Verify kernel alone
	kernel
		.verify()
		.map_err(|e| Error::Multisig(format!("kernel verify: {}", e)))?;

	// Assemble transaction
	let tx_inputs: Vec<Input> = inputs
		.iter()
		.map(|o| Input::new(OutputFeatures::Plain, o.commit))
		.collect();
	let tx_outputs: Vec<Output> = new_outputs
		.iter()
		.map(|o| Output::new(OutputFeatures::Plain, o.commit, o.proof))
		.collect();

	let offset = BlindingFactor::from_secret_key(session.offset.clone());
	let tx = Transaction::new(Inputs::from(tx_inputs.as_slice()), &tx_outputs, &[kernel])
		.with_offset(offset);

	// Full validation (rangeproofs + kernel sigs + kernel sums)
	tx.validate(Weighting::AsTransaction)
		.map_err(|e| Error::Multisig(format!("tx validate failed: {}", e)))?;

	Ok(MultisigSpendResult {
		tx,
		outputs: new_outputs,
		excess,
		session_id: session.session_id,
	})
}

/// Build a self-send (change-only) that consolidates inputs into one output.
pub fn build_self_send(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	inputs: &[MultisigOutput],
	output_number: u64,
	fee: u64,
	session_id: impl AsRef<[u8]>,
) -> Result<MultisigSpendResult, Error> {
	let in_sum: u64 = inputs.iter().map(|o| o.coin.value).sum();
	if in_sum <= fee {
		return Err(Error::Multisig("inputs too small for fee".into()));
	}
	let out_value = in_sum - fee;
	let out = CoinId::new(output_number, out_value);
	build_multisig_spend(secp, public_poly, quorum, inputs, &[out], fee, session_id)
}

/// Convenience: create a single funded output then spend it (local-sim E2E).
///
/// Returns `(funding_output, spend_result)`.
pub fn demo_fund_and_spend(
	secp: &Secp256k1,
	state: &MultisigWalletState,
	quorum: &[ActorPoint],
	fund_coin: CoinId,
	change_number: u64,
	fee: u64,
) -> Result<(MultisigOutput, MultisigSpendResult), Error> {
	let funding = create_multisig_output(secp, &state.config.public_poly, quorum, &fund_coin)?;
	let spend = build_self_send(
		secp,
		&state.config.public_poly,
		quorum,
		&[funding.clone()],
		change_number,
		fee,
		b"msig-e2e-demo",
	)?;
	Ok((funding, spend))
}

/// Extract quorum ActorPoints from a single MultisigWalletState (one share each).
///
/// For local-sim where all actors' states are available, prefer
/// [`quorum_from_states`].
pub fn quorum_from_state(state: &MultisigWalletState) -> Vec<ActorPoint> {
	// Single actor cannot form a threshold quorum alone unless M=1
	state
		.shares
		.iter()
		.map(|s| ActorPoint {
			x: s.x.clone(),
			y: s.y.clone(),
		})
		.collect()
}

/// Build a **canonical** quorum from several wallet states (one share index 0 each).
///
/// Order is sorted by x-coordinate (C-07); index 0 is the mix/offset role.
pub fn quorum_from_states(states: &[MultisigWalletState]) -> Result<Vec<ActorPoint>, Error> {
	if states.is_empty() {
		return Err(Error::Multisig("empty states for quorum".into()));
	}
	let mut q = Vec::new();
	for st in states {
		if st.shares.is_empty() {
			return Err(Error::Multisig("state has no shares".into()));
		}
		q.push(ActorPoint {
			x: st.shares[0].x.clone(),
			y: st.shares[0].y.clone(),
		});
	}
	canonical_quorum(&q)
}

/// Assemble a Grin transaction from multiparty artifacts (no secret shares).
///
/// Used after networked CreateOutput + Spend sessions complete: inputs are
/// known commitments, outputs carry multiparty rangeproofs, and the kernel
/// signature + aggregated pubs come from FROST. Offset is re-derived from the
/// public poly + spend session id (deterministic).
///
/// `session_id` must be the durable spend session id bytes (same as on the
/// negotiator record). `sig` / `agg` come from
/// [`super::session::Negotiator::result_kernel`].
pub fn assemble_from_kernel_results(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	session_id: &[u8],
	fee: u64,
	inputs: &[MultisigOutput],
	outputs: &[MultisigOutput],
	sig: crate::grin_util::secp::Signature,
	agg: &super::kernel::AggregatedKernelPubs,
) -> Result<Transaction, Error> {
	use super::kernel::{create_kernel_session, excess_commitment, plain_features, verify_kernel_sig};
	use super::rangeproof::{coin_pedersen_commit_public, verify_rangeproof};

	if inputs.is_empty() || outputs.is_empty() {
		return Err(Error::Multisig("assemble needs inputs and outputs".into()));
	}
	let in_sum: u64 = inputs.iter().map(|o| o.coin.value).sum();
	let out_sum: u64 = outputs.iter().map(|o| o.coin.value).sum();
	if in_sum != out_sum.saturating_add(fee) {
		return Err(Error::Multisig(format!(
			"value imbalance: inputs {} != outputs {} + fee {}",
			in_sum, out_sum, fee
		)));
	}
	for o in inputs.iter().chain(outputs.iter()) {
		let expected = coin_pedersen_commit_public(secp, public_poly, &o.coin)?;
		if expected != o.commit {
			return Err(Error::Multisig(format!(
				"commit mismatch for coin #{}",
				o.coin.number
			)));
		}
	}
	for o in outputs {
		verify_rangeproof(secp, o.commit, o.proof, None)?;
	}

	let in_ids: Vec<CoinId> = inputs.iter().map(|o| o.coin.clone()).collect();
	let out_ids: Vec<CoinId> = outputs.iter().map(|o| o.coin.clone()).collect();
	let features = plain_features(fee)?;
	let session = create_kernel_session(secp, public_poly, session_id, features, in_ids, out_ids)?;
	verify_kernel_sig(secp, &sig, agg, &session)?;
	let excess = excess_commitment(secp, agg)?;
	let kernel = TxKernel {
		features: session.features.clone(),
		excess,
		excess_sig: sig,
	};
	kernel
		.verify()
		.map_err(|e| Error::Multisig(format!("kernel verify: {}", e)))?;

	let tx_inputs: Vec<Input> = inputs
		.iter()
		.map(|o| Input::new(OutputFeatures::Plain, o.commit))
		.collect();
	let tx_outputs: Vec<Output> = outputs
		.iter()
		.map(|o| Output::new(OutputFeatures::Plain, o.commit, o.proof))
		.collect();
	let offset = BlindingFactor::from_secret_key(session.offset.clone());
	let tx = Transaction::new(Inputs::from(tx_inputs.as_slice()), &tx_outputs, &[kernel])
		.with_offset(offset);
	tx.validate(Weighting::AsTransaction)
		.map_err(|e| Error::Multisig(format!("tx validate failed: {}", e)))?;
	Ok(tx)
}

/// Local-sim epoch consolidation: sweep `inputs` into one new coin under the
/// **same** ceremony poly (membership change still requires re-DKG + this
/// pattern on the new poly after outputs are re-created).
pub fn build_epoch_sweep_local(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	inputs: &[MultisigOutput],
	output_number: u64,
	fee: u64,
	session_tag: impl AsRef<[u8]>,
) -> Result<MultisigSpendResult, Error> {
	build_self_send(
		secp,
		public_poly,
		quorum,
		inputs,
		output_number,
		fee,
		session_tag,
	)
}

/// Cross-epoch MultiTx (local sim): spend **old**-poly inputs into **new**-poly
/// outputs. Both quorums must be the same roster (matching x-coordinates) with
/// shares from two successive DKG epochs (C-13 re-DKG + sweep).
///
/// Networked multiparty would run CreateOutput under the new ceremony, then a
/// specialized cross-epoch FROST Spend; this path is the in-process equivalent.
pub fn build_cross_epoch_spend(
	secp: &Secp256k1,
	old_poly: &PublicPoly,
	old_quorum: &[ActorPoint],
	new_poly: &PublicPoly,
	new_quorum: &[ActorPoint],
	inputs: &[MultisigOutput],
	new_output_coins: &[CoinId],
	fee: u64,
	session_id: impl AsRef<[u8]>,
) -> Result<MultisigSpendResult, Error> {
	use super::kernel::{excess_commitment, run_kernel_sign_local_cross_epoch};
	use super::rangeproof::coin_pedersen_commit_public;

	if inputs.is_empty() || new_output_coins.is_empty() {
		return Err(Error::Multisig(
			"cross-epoch spend needs inputs and outputs".into(),
		));
	}
	let in_sum: u64 = inputs.iter().map(|o| o.coin.value).sum();
	let out_sum: u64 = new_output_coins.iter().map(|c| c.value).sum();
	if in_sum != out_sum.saturating_add(fee) {
		return Err(Error::Multisig(format!(
			"value imbalance: inputs {} != outputs {} + fee {}",
			in_sum, out_sum, fee
		)));
	}
	// Verify input commits against old poly.
	for o in inputs {
		let expected = coin_pedersen_commit_public(secp, old_poly, &o.coin)?;
		if expected != o.commit {
			return Err(Error::Multisig(format!(
				"input coin #{} commit does not match old poly",
				o.coin.number
			)));
		}
	}

	// New outputs: multiparty RP under the **new** ceremony.
	let mut new_outputs = Vec::with_capacity(new_output_coins.len());
	for coin in new_output_coins {
		new_outputs.push(create_multisig_output(secp, new_poly, new_quorum, coin)?);
	}

	let in_ids: Vec<CoinId> = inputs.iter().map(|o| o.coin.clone()).collect();
	let out_ids: Vec<CoinId> = new_output_coins.to_vec();
	let (sig, agg, session) = run_kernel_sign_local_cross_epoch(
		secp,
		old_poly,
		old_quorum,
		new_poly,
		new_quorum,
		session_id.as_ref(),
		fee,
		in_ids,
		out_ids,
	)?;

	let excess = excess_commitment(secp, &agg)?;
	let kernel = TxKernel {
		features: session.features.clone(),
		excess,
		excess_sig: sig,
	};
	kernel
		.verify()
		.map_err(|e| Error::Multisig(format!("kernel verify: {}", e)))?;

	let tx_inputs: Vec<Input> = inputs
		.iter()
		.map(|o| Input::new(OutputFeatures::Plain, o.commit))
		.collect();
	let tx_outputs: Vec<Output> = new_outputs
		.iter()
		.map(|o| Output::new(OutputFeatures::Plain, o.commit, o.proof))
		.collect();
	let offset = BlindingFactor::from_secret_key(session.offset.clone());
	let tx = Transaction::new(Inputs::from(tx_inputs.as_slice()), &tx_outputs, &[kernel])
		.with_offset(offset);
	tx.validate(Weighting::AsTransaction)
		.map_err(|e| Error::Multisig(format!("tx validate failed: {}", e)))?;

	Ok(MultisigSpendResult {
		tx,
		outputs: new_outputs,
		excess,
		session_id: session.session_id,
	})
}

/// Serialize a transaction to hex (protocol v3 body encoding).
pub fn tx_to_hex(tx: &Transaction) -> Result<String, Error> {
	let bytes = ser::ser_vec(tx, ser::ProtocolVersion(3))
		.map_err(|e| Error::Multisig(format!("tx ser: {}", e)))?;
	Ok(bytes.to_hex())
}

/// Deserialize a transaction from hex.
pub fn tx_from_hex(hex: &str) -> Result<Transaction, Error> {
	let bytes = from_hex(hex).map_err(|e| Error::Multisig(format!("tx hex: {}", e)))?;
	ser::deserialize(
		&mut &bytes[..],
		ser::ProtocolVersion(3),
		ser::DeserializationMode::default(),
	)
	.map_err(|e| Error::Multisig(format!("tx deser: {}", e)))
}

/// JSON-serializable result of an in-process E2E demo.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigDemoTxResult {
	/// Threshold M.
	pub threshold: usize,
	/// Total actors N.
	pub total: usize,
	/// Funded coin value.
	pub fund_value: u64,
	/// Change output value after fee.
	pub change_value: u64,
	/// Fee paid.
	pub fee: u64,
	/// Kernel excess commitment (hex).
	pub kernel_excess: String,
	/// Transaction id / hash (hex).
	pub tx_hash: String,
	/// Full transaction body (hex) for optional `post_tx`.
	pub tx_hex: String,
}

/// Run E2E demo and return a serializable summary (for Owner API / CLI).
pub fn run_demo_tx(
	threshold: usize,
	total: usize,
	fee: u64,
) -> Result<MultisigDemoTxResult, Error> {
	use crate::grin_util::secp::ContextFlag;
	use crate::multisig::dkg::run_dkg_local;
	use crate::multisig::types::{ActorId, CeremonyId, ThresholdParams};

	// SECURITY (C-01): do NOT mutate the chain type here. This function is
	// reachable from the production Owner API; calling `set_local_chain_type`
	// would install a thread-local override that silently reconfigures
	// consensus parameters for every subsequent operation on the calling
	// thread. The demo instead runs under whatever chain type the host has
	// already configured — always set inside a running wallet, and set
	// explicitly by the unit tests that exercise this path.
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let params = ThresholdParams::new_allow_low_degree(threshold, total)?;
	let actors: Vec<_> = (0..total as u32).map(ActorId::from_index).collect();
	let states = run_dkg_local(&secp, CeremonyId::new(), params, actors)?;
	let q = quorum_from_states(&states)?;
	let fund_value = 1_000_000_000u64;
	let fund = CoinId::new(1, fund_value);
	let (_funding, spend) = demo_fund_and_spend(&secp, &states[0], &q, fund, 2, fee)?;
	Ok(MultisigDemoTxResult {
		threshold,
		total,
		fund_value,
		change_value: spend.outputs[0].coin.value,
		fee,
		kernel_excess: spend.excess.0.to_vec().to_hex(),
		tx_hash: format!("{}", spend.tx.hash()),
		tx_hex: tx_to_hex(&spend.tx)?,
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_core::global;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};
	use crate::multisig::dkg::run_dkg_local;
	use crate::multisig::share::{canonical_quorum, ActorPoint};
	use crate::multisig::types::{ActorId, CeremonyId, ThresholdParams};

	fn setup_2of3(secp: &Secp256k1) -> (PublicPoly, Vec<ActorPoint>, MultisigWalletState) {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let params = ThresholdParams::new_allow_low_degree(2, 3).unwrap();
		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let states = run_dkg_local(secp, CeremonyId::new(), params, actors).unwrap();
		let q = canonical_quorum(&[
			ActorPoint::from(&states[0].shares[0]),
			ActorPoint::from(&states[1].shares[0]),
		])
		.unwrap();
		(states[0].config.public_poly.clone(), q, states[0].clone())
	}

	#[test]
	fn e2e_fund_and_spend_validates() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (_pp, q, state) = setup_2of3(&secp);
		let fund = CoinId::new(1, 1_000_000_000);
		let fee = 1_000_000;
		let (funding, spend) = demo_fund_and_spend(&secp, &state, &q, fund, 2, fee).unwrap();
		assert_eq!(funding.coin.value, 1_000_000_000);
		assert_eq!(spend.outputs.len(), 1);
		assert_eq!(spend.outputs[0].coin.value, 1_000_000_000 - fee);
		// re-validate
		spend
			.tx
			.validate(Weighting::AsTransaction)
			.expect("tx must validate");
	}

	#[test]
	fn e2e_two_outputs_with_payment() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, _) = setup_2of3(&secp);
		let funding =
			create_multisig_output(&secp, &pp, &q, &CoinId::new(10, 500_000_000)).unwrap();
		// pay 100, change rest, fee 1
		let fee = 1_000_000;
		let pay = CoinId::new(11, 100_000_000);
		let change = CoinId::new(12, 500_000_000 - 100_000_000 - fee);
		let res =
			build_multisig_spend(&secp, &pp, &q, &[funding], &[pay, change], fee, b"pay-sess")
				.unwrap();
		assert_eq!(res.outputs.len(), 2);
		res.tx.validate(Weighting::AsTransaction).unwrap();
	}

	#[test]
	fn rejects_value_imbalance() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, _) = setup_2of3(&secp);
		let funding = create_multisig_output(&secp, &pp, &q, &CoinId::new(1, 100)).unwrap();
		let err = build_multisig_spend(
			&secp,
			&pp,
			&q,
			&[funding],
			&[CoinId::new(2, 50)],
			1, // 100 != 50+1
			b"bad",
		)
		.unwrap_err();
		match err {
			Error::Multisig(m) => assert!(m.contains("imbalance")),
			_ => panic!("unexpected"),
		}
	}

	#[test]
	fn assemble_from_kernel_results_validates() {
		use super::super::kernel::run_kernel_sign_local;
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, _) = setup_2of3(&secp);
		let fee = 1_000u64;
		let funding =
			create_multisig_output(&secp, &pp, &q, &CoinId::new(1, 1_000_000)).unwrap();
		let change = create_multisig_output(
			&secp,
			&pp,
			&q,
			&CoinId::new(2, 1_000_000 - fee),
		)
		.unwrap();
		let (sig, agg, session) = run_kernel_sign_local(
			&secp,
			&pp,
			&q,
			b"assemble-sess",
			fee,
			vec![funding.coin.clone()],
			vec![change.coin.clone()],
		)
		.unwrap();
		let tx = assemble_from_kernel_results(
			&secp,
			&pp,
			&session.session_id,
			fee,
			&[funding],
			&[change],
			sig,
			&agg,
		)
		.unwrap();
		tx.validate(Weighting::AsTransaction).unwrap();
	}

	#[test]
	fn epoch_sweep_local_consolidates() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, _) = setup_2of3(&secp);
		let a = create_multisig_output(&secp, &pp, &q, &CoinId::new(1, 400_000)).unwrap();
		let b = create_multisig_output(&secp, &pp, &q, &CoinId::new(2, 600_000)).unwrap();
		let fee = 1_000;
		let res = build_epoch_sweep_local(&secp, &pp, &q, &[a, b], 99, fee, b"sweep").unwrap();
		assert_eq!(res.outputs.len(), 1);
		assert_eq!(res.outputs[0].coin.number, 99);
		assert_eq!(res.outputs[0].coin.value, 1_000_000 - fee);
		res.tx.validate(Weighting::AsTransaction).unwrap();
	}

	#[test]
	fn cross_epoch_spend_validates() {
		// Same roster re-DKGs to a new poly, then spends old UTXO → new epoch coin.
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 3).unwrap();
		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let old_states =
			run_dkg_local(&secp, CeremonyId::new(), params.clone(), actors.clone()).unwrap();
		let new_states =
			run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let old_pp = old_states[0].config.public_poly.clone();
		let new_pp = new_states[0].config.public_poly.clone();
		// Same two actors (indices 0,1) form both quorums — x coords match by actor id.
		let old_q = canonical_quorum(&[
			ActorPoint::from(&old_states[0].shares[0]),
			ActorPoint::from(&old_states[1].shares[0]),
		])
		.unwrap();
		let new_q = canonical_quorum(&[
			ActorPoint::from(&new_states[0].shares[0]),
			ActorPoint::from(&new_states[1].shares[0]),
		])
		.unwrap();
		// Confirm x-coords align after sort.
		for (a, b) in old_q.iter().zip(new_q.iter()) {
			assert_eq!(a.x.0, b.x.0);
		}
		assert_ne!(
			old_pp.coefficients, new_pp.coefficients,
			"epochs must have distinct polys"
		);

		let fee = 1_000u64;
		let funding =
			create_multisig_output(&secp, &old_pp, &old_q, &CoinId::new(1, 1_000_000)).unwrap();
		let res = build_cross_epoch_spend(
			&secp,
			&old_pp,
			&old_q,
			&new_pp,
			&new_q,
			&[funding],
			&[CoinId::new(10, 1_000_000 - fee)],
			fee,
			b"cross-epoch",
		)
		.unwrap();
		assert_eq!(res.outputs.len(), 1);
		// Output commit must match **new** poly.
		let expected = super::super::rangeproof::coin_pedersen_commit_public(
			&secp,
			&new_pp,
			&res.outputs[0].coin,
		)
		.unwrap();
		assert_eq!(res.outputs[0].commit, expected);
		res.tx.validate(Weighting::AsTransaction).unwrap();
	}

	#[test]
	fn multiparty_soak_rounds() {
		// Lightweight soak: repeated fund→spend cycles for a 2-of-3 quorum.
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, _) = setup_2of3(&secp);
		let fee = 1_000u64;
		for round in 0..5u64 {
			let fund_n = round * 10 + 1;
			let chg_n = round * 10 + 2;
			let funding = create_multisig_output(
				&secp,
				&pp,
				&q,
				&CoinId::new(fund_n, 500_000 + round * 1_000),
			)
			.unwrap();
			let value = funding.coin.value;
			let spend = build_self_send(
				&secp,
				&pp,
				&q,
				&[funding],
				chg_n,
				fee,
				format!("soak-{}", round).as_bytes(),
			)
			.unwrap();
			assert_eq!(spend.outputs[0].coin.value, value - fee);
			spend.tx.validate(Weighting::AsTransaction).unwrap();
		}
	}

	#[test]
	fn demo_tx_hex_roundtrip() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let res = run_demo_tx(2, 2, 1_000_000).unwrap();
		assert_eq!(res.threshold, 2);
		assert!(res.change_value + res.fee == res.fund_value);
		let tx = tx_from_hex(&res.tx_hex).unwrap();
		tx.validate(Weighting::AsTransaction).unwrap();
	}

	#[test]
	fn three_of_three_e2e() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(3, 3).unwrap();
		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let q = quorum_from_states(&states).unwrap();
		let fund = CoinId::new(1, 10_000_000);
		let (funding, spend) = demo_fund_and_spend(&secp, &states[0], &q, fund, 2, 100).unwrap();
		assert!(funding.proof.plen > 0);
		spend.tx.validate(Weighting::AsTransaction).unwrap();
	}
}
