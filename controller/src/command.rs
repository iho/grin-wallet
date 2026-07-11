// Copyright 2021 The Grin Developers
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

//! Grin wallet command-line function implementations

use crate::api::TLSConfig;
use crate::apiwallet::{try_slatepack_sync_workflow, Owner};
use crate::config::{TorConfig, WalletConfig, WALLET_CONFIG_FILE_NAME};
use crate::core::{core, global};
use crate::error::Error;
use crate::impls::PathToSlatepack;
use crate::impls::SlateGetter as _;
use crate::keychain;
use crate::libwallet::{
	self, InitTxArgs, IssueInvoiceTxArgs, NodeClient, PaymentProof, Slate, SlateState, Slatepack,
	SlatepackAddress, Slatepacker, SlatepackerArgs, WalletLCProvider,
};
use crate::util::secp::key::SecretKey;
use crate::util::{Mutex, ToHex, ZeroingString};
use crate::{controller, display};
use ::core::time;
use qr_code::QrCode;
use serde_json as json;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

fn show_recovery_phrase(phrase: ZeroingString) {
	println!("Your recovery phrase is:");
	println!();
	println!("{}", &*phrase);
	println!();
	println!("Please back-up these words in a non-digital format.");
}

/// Arguments common to all wallet commands
#[derive(Clone)]
pub struct GlobalArgs {
	pub account: String,
	pub api_secret: Option<String>,
	pub node_api_secret: Option<String>,
	pub show_spent: bool,
	pub password: Option<ZeroingString>,
	pub tls_conf: Option<TLSConfig>,
}

/// Arguments for init command
pub struct InitArgs {
	/// BIP39 recovery phrase length
	pub list_length: usize,
	pub password: ZeroingString,
	pub config: WalletConfig,
	pub recovery_phrase: Option<ZeroingString>,
	pub restore: bool,
}

/// Write config (default if None), initiate the wallet
pub fn init<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	_g_args: &GlobalArgs,
	args: InitArgs,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	// Assume global chain type has already been initialized.
	let chain_type = global::get_chain_type();

	let mut w_lock = owner_api.wallet_inst.lock();
	let p = w_lock.lc_provider()?;
	p.create_config(&chain_type, WALLET_CONFIG_FILE_NAME, None, None, None)?;
	p.create_wallet(
		None,
		args.recovery_phrase,
		args.list_length,
		args.password.clone(),
		test_mode,
	)?;

	let m = p.get_mnemonic(None, args.password)?;
	show_recovery_phrase(m);
	Ok(())
}

/// Argument for recover
pub struct RecoverArgs {
	pub passphrase: ZeroingString,
}

pub fn recover<L, C, K>(owner_api: &mut Owner<L, C, K>, args: RecoverArgs) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut w_lock = owner_api.wallet_inst.lock();
	let p = w_lock.lc_provider()?;
	let m = p.get_mnemonic(None, args.passphrase)?;
	show_recovery_phrase(m);
	Ok(())
}

pub fn rewind_hash<'a, L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let rewind_hash = api.get_rewind_hash(m)?;
		println!();
		println!("Wallet Rewind Hash");
		println!("-------------------------------------");
		println!("{}", rewind_hash);
		println!();
		Ok(())
	})?;
	Ok(())
}

/// Arguments for rewind hash view wallet scan command
pub struct ViewWalletScanArgs {
	pub rewind_hash: String,
	pub start_height: Option<u64>,
	pub backwards_from_tip: Option<u64>,
}

pub fn scan_rewind_hash<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	args: ViewWalletScanArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, None, Some(owner_api), |api, m| {
		let rewind_hash = args.rewind_hash;
		let tip_height = api.node_height(m)?.height;
		let start_height = match args.backwards_from_tip {
			Some(b) => tip_height.saturating_sub(b),
			None => match args.start_height {
				Some(s) => s,
				None => 1,
			},
		};
		warn!(
			"Starting view wallet output scan from height {} ...",
			start_height
		);
		let result = api.scan_rewind_hash(rewind_hash, Some(start_height));
		let deci_sec = time::Duration::from_millis(100);
		thread::sleep(deci_sec);
		match result {
			Ok(res) => {
				warn!("View wallet check complete");
				if res.total_balance != 0 {
					display::view_wallet_output(res.clone(), tip_height, dark_scheme)?;
				}
				display::view_wallet_balance(res.clone(), tip_height, dark_scheme);
				Ok(())
			}
			Err(e) => {
				error!("View wallet check failed: {}", e);
				Err(e)
			}
		}
	})?;
	Ok(())
}

/// Arguments for listen command
pub struct ListenArgs {}

pub fn listen<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	config: &WalletConfig,
	tor_config: &TorConfig,
	_args: &ListenArgs,
	g_args: &GlobalArgs,
	cli_mode: bool,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let wallet_inst = owner_api.wallet_inst.clone();
	let config = config.clone();
	let tor_config = tor_config.clone();
	let g_args = g_args.clone();
	let api_thread = thread::Builder::new()
		.name("wallet-http-listener".to_string())
		.spawn(move || {
			let res = controller::foreign_listener(
				wallet_inst,
				keychain_mask,
				&config.api_listen_addr(),
				g_args.tls_conf.clone(),
				tor_config.use_tor_listener,
				test_mode,
				Some(tor_config.clone()),
			);
			if let Err(e) = res {
				error!("Error starting listener: {}", e);
			}
		});
	if let Ok(t) = api_thread {
		if !cli_mode {
			let r = t.join();
			if let Err(_) = r {
				error!("Error starting listener");
				return Err(Error::ListenerError);
			}
		}
	}
	Ok(())
}

pub fn owner_api<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<SecretKey>,
	config: &WalletConfig,
	tor_config: &TorConfig,
	g_args: &GlobalArgs,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	// keychain mask needs to be a sinlge instance, in case the foreign API is
	// also being run at the same time
	let km = Arc::new(Mutex::new(keychain_mask));
	let res = controller::owner_listener(
		owner_api.wallet_inst.clone(),
		km,
		config.owner_api_listen_addr().as_str(),
		g_args.api_secret.clone(),
		g_args.tls_conf.clone(),
		config.owner_api_include_foreign,
		Some(tor_config.clone()),
		test_mode,
	);
	if let Err(e) = res {
		return Err(Error::LibWallet(e));
	}
	Ok(())
}

/// Arguments for account command
pub struct AccountArgs {
	pub create: Option<String>,
}

pub fn account<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: AccountArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	if args.create.is_none() {
		let res = controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let acct_mappings = api.accounts(m)?;
			// give logging thread a moment to catch up
			thread::sleep(Duration::from_millis(200));
			display::accounts(acct_mappings);
			Ok(())
		});
		if let Err(e) = res {
			error!("Error listing accounts: {}", e);
			return Err(Error::LibWallet(e));
		}
	} else {
		let label = args.create.unwrap();
		let res = controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			api.create_account_path(m, &label)?;
			thread::sleep(Duration::from_millis(200));
			info!("Account: '{}' Created!", label);
			Ok(())
		});
		if let Err(e) = res {
			thread::sleep(Duration::from_millis(200));
			error!("Error creating account '{}': {}", label, e);
			return Err(Error::LibWallet(e));
		}
	}
	Ok(())
}

/// Arguments for the send command
#[derive(Clone)]
pub struct SendArgs {
	pub amount: u64,
	pub amount_includes_fee: bool,
	pub use_max_amount: bool,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub estimate_selection_strategies: bool,
	pub late_lock: bool,
	pub dest: String,
	pub change_outputs: usize,
	pub fluff: bool,
	pub max_outputs: usize,
	pub target_slate_version: Option<u16>,
	pub payment_proof_address: Option<SlatepackAddress>,
	pub ttl_blocks: Option<u64>,
	pub skip_tor: bool,
	pub outfile: Option<String>,
	pub bridge: Option<String>,
	pub slatepack_qr: bool,
}

pub fn send<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	tor_config: Option<TorConfig>,
	args: SendArgs,
	dark_scheme: bool,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut slate = Slate::blank(2, false);
	let mut amount = args.amount;
	if args.use_max_amount {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let (_, wallet_info) =
				api.retrieve_summary_info(m, true, args.minimum_confirmations)?;
			amount = wallet_info.amount_currently_spendable;
			Ok(())
		})?;
	};
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		if args.estimate_selection_strategies {
			let strategies = vec!["smallest", "all"]
				.into_iter()
				.map(|strategy| {
					let init_args = InitTxArgs {
						src_acct_name: None,
						amount: amount,
						amount_includes_fee: Some(args.amount_includes_fee),
						minimum_confirmations: args.minimum_confirmations,
						max_outputs: args.max_outputs as u32,
						num_change_outputs: args.change_outputs as u32,
						selection_strategy_is_use_all: strategy == "all",
						estimate_only: Some(true),
						..Default::default()
					};
					let slate = api.init_send_tx(m, init_args)?;
					Ok((strategy, slate.amount, slate.fee_fields))
				})
				.collect::<Result<Vec<_>, grin_wallet_libwallet::Error>>()?;
			display::estimate(amount, strategies, dark_scheme);
			return Ok(());
		} else {
			let init_args = InitTxArgs {
				src_acct_name: None,
				amount: amount,
				amount_includes_fee: Some(args.amount_includes_fee),
				minimum_confirmations: args.minimum_confirmations,
				max_outputs: args.max_outputs as u32,
				num_change_outputs: args.change_outputs as u32,
				selection_strategy_is_use_all: args.selection_strategy == "all",
				target_slate_version: args.target_slate_version,
				payment_proof_recipient_address: args.payment_proof_address.clone(),
				ttl_blocks: args.ttl_blocks,
				send_args: None,
				late_lock: Some(args.late_lock),
				..Default::default()
			};
			let result = api.init_send_tx(m, init_args);
			slate = match result {
				Ok(s) => {
					info!(
						"Tx created: {} grin to {} (strategy '{}')",
						core::amount_to_hr_string(amount, false),
						args.dest,
						args.selection_strategy,
					);
					s
				}
				Err(e) => {
					info!("Tx not created: {}", e);
					return Err(e);
				}
			};
		}
		Ok(())
	})?;

	if args.estimate_selection_strategies {
		return Ok(());
	}

	let tor_config = match tor_config {
		Some(mut c) => {
			if let Some(b) = args.bridge.clone() {
				c.bridge.bridge_line = Some(b);
			}
			c.skip_send_attempt = Some(args.skip_tor);
			Some(c)
		}
		None => None,
	};

	let res = try_slatepack_sync_workflow(&slate, &args.dest, tor_config, None, false, test_mode);

	match res {
		Ok(Some(s)) => {
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				api.tx_lock_outputs(m, &s)?;
				let ret_slate = api.finalize_tx(m, &s)?;
				let result = api.post_tx(m, &ret_slate, args.fluff);
				match result {
					Ok(_) => {
						println!("Tx sent successfully",);
						Ok(())
					}
					Err(e) => {
						error!("Tx sent fail: {}", e);
						Err(e.into())
					}
				}
			})?;
		}
		Ok(None) => {
			output_slatepack(
				owner_api,
				keychain_mask,
				&slate,
				args.dest.as_str(),
				args.outfile,
				true,
				false,
				args.slatepack_qr,
			)?;
		}
		Err(e) => return Err(e.into()),
	}
	Ok(())
}

pub fn output_slatepack<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	dest: &str,
	out_file_override: Option<String>,
	lock: bool,
	finalizing: bool,
	show_qr: bool,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	// Output the slatepack file to stdout and to a file
	let mut message = String::from("");
	let mut address = None;
	let mut tld = String::from("");
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		address = match SlatepackAddress::try_from(dest) {
			Ok(a) => Some(a),
			Err(_) => None,
		};
		// encrypt for recipient by default
		let recipients = match address.clone() {
			Some(a) => vec![a],
			None => vec![],
		};
		message = api.create_slatepack_message(m, &slate, Some(0), recipients)?;
		tld = api.get_top_level_directory()?;
		Ok(())
	})?;

	// create a directory to which files will be output
	let slate_dir = format!("{}/{}", tld, "slatepack");
	let _ = std::fs::create_dir_all(slate_dir.clone());
	let out_file_name = match out_file_override {
		None => format!("{}/{}.{}.slatepack", slate_dir, slate.id, slate.state),
		Some(f) => f,
	};

	if lock {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			api.tx_lock_outputs(m, &slate)?;
			Ok(())
		})?;
	}

	println!("{}", out_file_name);
	let mut output = File::create(out_file_name.clone())?;
	output.write_all(&message.as_bytes())?;
	output.sync_all()?;

	println!();
	if !finalizing {
		println!("Slatepack data follows. Please provide this output to the other party");
	} else {
		println!("Slatepack data follows.");
	}
	println!();
	println!("--- CUT BELOW THIS LINE ---");
	println!();
	println!("{}", message);
	println!("--- CUT ABOVE THIS LINE ---");
	println!();
	println!("Slatepack data was also output to");
	println!();
	println!("{}", out_file_name);
	println!();
	if show_qr {
		if let Ok(qr_string) = QrCode::new(message) {
			println!("{}", qr_string.to_string(false, 3));
			println!();
		}
	}
	if address.is_some() {
		println!("The slatepack data is encrypted for the recipient only");
	} else {
		println!("The slatepack data is NOT encrypted");
	}
	println!();
	Ok(())
}

// Parse a slate and slatepack from a message
pub fn parse_slatepack<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	filename: Option<String>,
	message: Option<String>,
) -> Result<(Slate, Option<SlatepackAddress>), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut ret_address = None;
	let slate = match filename {
		Some(f) => {
			// otherwise, get slate from slatepack
			let mut sl = None;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let dec_key = api.get_slatepack_secret_key(m, 0)?;
				let packer = Slatepacker::new(SlatepackerArgs {
					sender: None,
					recipients: vec![],
					dec_key: Some(&dec_key),
				});
				let pts = PathToSlatepack::new(f.into(), &packer, true);
				sl = Some(pts.get_tx()?.0);
				ret_address = pts.get_slatepack(true)?.sender;
				Ok(())
			})?;
			sl
		}
		None => None,
	};

	let slate = match slate {
		Some(s) => s,
		None => {
			// try and parse directly from input_slatepack_message
			let mut slate = Slate::blank(2, false);
			match message {
				Some(message) => {
					controller::owner_single_use(
						None,
						keychain_mask,
						Some(owner_api),
						|api, m| {
							slate =
								api.slate_from_slatepack_message(m, message.clone(), vec![0])?;
							let slatepack =
								api.decode_slatepack_message(m, message.clone(), vec![0])?;
							ret_address = slatepack.sender;
							Ok(())
						},
					)?;
				}
				None => {
					let msg = "No slate provided via file or direct input";
					return Err(Error::GenericError(msg.into()).into());
				}
			}
			slate
		}
	};
	Ok((slate, ret_address))
}

/// Receive command argument
#[derive(Clone)]
pub struct ReceiveArgs {
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub skip_tor: bool,
	pub outfile: Option<String>,
	pub bridge: Option<String>,
	pub slatepack_qr: bool,
}

pub fn receive<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: ReceiveArgs,
	tor_config: Option<TorConfig>,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (mut slate, ret_address) = parse_slatepack(
		owner_api,
		keychain_mask,
		args.input_file,
		args.input_slatepack_message,
	)?;

	let km = match keychain_mask.as_ref() {
		None => None,
		Some(&m) => Some(m.to_owned()),
	};

	let tor_config = match tor_config {
		Some(mut c) => {
			if let Some(b) = args.bridge {
				c.bridge.bridge_line = Some(b);
			}
			c.skip_send_attempt = Some(args.skip_tor);
			Some(c)
		}
		None => None,
	};

	controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
		slate = api.receive_tx(&slate, Some(&g_args.account), None)?;
		Ok(())
	})?;

	let dest = match ret_address {
		Some(a) => String::try_from(&a).unwrap(),
		None => String::from(""),
	};

	let res = try_slatepack_sync_workflow(&slate, &dest, tor_config, None, true, test_mode);

	match res {
		Ok(Some(_)) => {
			println!();
			println!(
				"Transaction recieved and sent back to sender at {} for finalization.",
				dest
			);
			println!();
			Ok(())
		}
		Ok(None) => {
			output_slatepack(
				owner_api,
				keychain_mask,
				&slate,
				&dest,
				args.outfile,
				false,
				false,
				args.slatepack_qr,
			)?;
			Ok(())
		}
		Err(e) => Err(e.into()),
	}
}

pub fn unpack<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ReceiveArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut slatepack = match args.input_file {
		Some(f) => {
			let packer = Slatepacker::new(SlatepackerArgs {
				sender: None,
				recipients: vec![],
				dec_key: None,
			});
			PathToSlatepack::new(f.into(), &packer, true).get_slatepack(false)?
		}
		None => match args.input_slatepack_message {
			Some(mes) => {
				let mut sp = Slatepack::default();
				controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
					sp = api.decode_slatepack_message(m, mes, vec![])?;
					Ok(())
				})?;
				sp
			}
			None => {
				return Err(Error::ArgumentError("Invalid Slatepack Input".into()).into());
			}
		},
	};
	println!();
	println!("SLATEPACK CONTENTS");
	println!("------------------");
	println!("{}", slatepack);
	println!("------------------");

	let packer = Slatepacker::new(SlatepackerArgs {
		sender: None,
		recipients: vec![],
		dec_key: None,
	});

	if slatepack.mode == 1 {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let dec_key = api.get_slatepack_secret_key(m, 0)?;
			match slatepack.try_decrypt_payload(Some(&dec_key)) {
				Ok(_) => {
					println!("Slatepack is encrypted for this wallet");
					println!();
					println!("DECRYPTED SLATEPACK");
					println!("-------------------");
					println!("{}", slatepack);
					let slate = packer.get_slate(&slatepack)?;
					println!();
					println!("DECRYPTED SLATE");
					println!("---------------");
					println!("{}", slate);
				}
				Err(_) => {
					println!("Slatepack payload cannot be decrypted by this wallet");
				}
			}
			Ok(())
		})?;
	} else {
		let slate = packer.get_slate(&slatepack)?;
		println!("Slatepack is not encrypted");
		println!();
		println!("SLATE");
		println!("-----");
		println!("{}", slate);
	}
	Ok(())
}

/// Finalize command args
#[derive(Clone)]
pub struct FinalizeArgs {
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub fluff: bool,
	pub nopost: bool,
	pub outfile: Option<String>,
	pub slatepack_qr: bool,
}

pub fn finalize<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: FinalizeArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (mut slate, _ret_address) = parse_slatepack(
		owner_api,
		keychain_mask,
		args.input_file.clone(),
		args.input_slatepack_message.clone(),
	)?;

	// Rather than duplicating the entire command, we'll just
	// try to determine what kind of finalization this is
	// based on the slate state
	let is_invoice = slate.state == SlateState::Invoice2;

	if is_invoice {
		let km = match keychain_mask.as_ref() {
			None => None,
			Some(&m) => Some(m.to_owned()),
		};
		controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
			slate = api.finalize_tx(&slate, false)?;
			Ok(())
		})?;
	} else {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			slate = api.finalize_tx(m, &slate)?;
			Ok(())
		})?;
	}

	if !&args.nopost {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let result = api.post_tx(m, &slate, args.fluff);
			match result {
				Ok(_) => {
					info!(
						"Transaction sent successfully, check the wallet again for confirmation."
					);
					println!("Transaction posted");
					Ok(())
				}
				Err(e) => {
					error!("Tx not sent: {}", e);
					Err(e)
				}
			}
		})?;
	}

	println!("Transaction finalized successfully");

	output_slatepack(
		owner_api,
		keychain_mask,
		&slate,
		"",
		args.outfile,
		false,
		true,
		args.slatepack_qr,
	)?;

	Ok(())
}

/// Issue Invoice Args
pub struct IssueInvoiceArgs {
	/// Slatepack address
	pub dest: String,
	/// issue invoice tx args
	pub issue_args: IssueInvoiceTxArgs,
	/// output file override
	pub outfile: Option<String>,
	/// show slatepack as QR code
	pub slatepack_qr: bool,
}

pub fn issue_invoice_tx<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: IssueInvoiceArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let issue_args = args.issue_args.clone();

	let mut slate = Slate::blank(2, false);
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		slate = api.issue_invoice_tx(m, issue_args)?;
		Ok(())
	})?;

	output_slatepack(
		owner_api,
		keychain_mask,
		&slate,
		args.dest.as_str(),
		args.outfile,
		false,
		false,
		args.slatepack_qr,
	)?;
	Ok(())
}

/// Arguments for the process_invoice command
pub struct ProcessInvoiceArgs {
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub ret_address: Option<SlatepackAddress>,
	pub max_outputs: usize,
	pub slate: Slate,
	pub estimate_selection_strategies: bool,
	pub ttl_blocks: Option<u64>,
	pub skip_tor: bool,
	pub outfile: Option<String>,
	pub bridge: Option<String>,
	pub slatepack_qr: bool,
}

/// Process invoice
pub fn process_invoice<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	tor_config: Option<TorConfig>,
	args: ProcessInvoiceArgs,
	dark_scheme: bool,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut slate = args.slate.clone();
	let dest = match args.ret_address.clone() {
		Some(a) => String::try_from(&a).unwrap(),
		None => String::from(""),
	};

	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		if args.estimate_selection_strategies {
			let strategies = vec!["smallest", "all"]
				.into_iter()
				.map(|strategy| {
					let init_args = InitTxArgs {
						src_acct_name: None,
						amount: slate.amount,
						minimum_confirmations: args.minimum_confirmations,
						max_outputs: args.max_outputs as u32,
						num_change_outputs: 1u32,
						selection_strategy_is_use_all: strategy == "all",
						estimate_only: Some(true),
						..Default::default()
					};
					let slate = api.init_send_tx(m, init_args).unwrap();
					(strategy, slate.amount, slate.fee_fields)
				})
				.collect();
			display::estimate(slate.amount, strategies, dark_scheme);
			return Ok(());
		} else {
			let init_args = InitTxArgs {
				src_acct_name: None,
				amount: 0,
				minimum_confirmations: args.minimum_confirmations,
				max_outputs: args.max_outputs as u32,
				num_change_outputs: 1u32,
				selection_strategy_is_use_all: args.selection_strategy == "all",
				ttl_blocks: args.ttl_blocks,
				send_args: None,
				..Default::default()
			};
			let result = api.process_invoice_tx(m, &slate, init_args);
			slate = match result {
				Ok(s) => {
					info!(
						"Invoice processed: {} grin (strategy '{}')",
						core::amount_to_hr_string(slate.amount, false),
						args.selection_strategy,
					);
					s
				}
				Err(e) => {
					info!("Tx not created: {}", e);
					return Err(e);
				}
			};
		}
		Ok(())
	})?;

	let tor_config = match tor_config {
		Some(mut c) => {
			if let Some(b) = args.bridge {
				c.bridge.bridge_line = Some(b);
			}
			c.skip_send_attempt = Some(args.skip_tor);
			Some(c)
		}
		None => None,
	};

	let res = try_slatepack_sync_workflow(&slate, &dest, tor_config, None, true, test_mode);

	match res {
		Ok(Some(_)) => {
			println!();
			println!(
				"Transaction paid and sent back to initiator at {} for finalization.",
				dest
			);
			println!();
			Ok(())
		}
		Ok(None) => {
			output_slatepack(
				owner_api,
				keychain_mask,
				&slate,
				&dest,
				args.outfile,
				true,
				false,
				args.slatepack_qr,
			)?;
			Ok(())
		}
		Err(e) => Err(e.into()),
	}
}

/// Info command args
pub struct InfoArgs {
	pub minimum_confirmations: u64,
}

pub fn info<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: InfoArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let (validated, wallet_info) =
			api.retrieve_summary_info(m, true, args.minimum_confirmations)?;
		display::info(
			&g_args.account,
			&wallet_info,
			validated || updater_running,
			dark_scheme,
		);
		Ok(())
	})?;
	Ok(())
}

pub fn outputs<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let res = api.node_height(m)?;
		let (validated, outputs) = api.retrieve_outputs(m, g_args.show_spent, true, None)?;
		display::outputs(
			&g_args.account,
			res.height,
			validated || updater_running,
			outputs,
			dark_scheme,
		)?;
		Ok(())
	})?;
	Ok(())
}

/// Txs command args
pub struct TxsArgs {
	pub id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
	pub count: Option<u32>,
}

pub fn txs<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: TxsArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let res = api.node_height(m)?;
		// Note advanced query args not currently supported by command line client
		let (validated, txs) = api.retrieve_txs(m, true, args.id, args.tx_slate_id, None)?;
		let include_status = !args.id.is_some() && !args.tx_slate_id.is_some();
		// If view count is specified, restrict the TX list to `txs.len() - count`
		let first_tx = args
			.count
			.map_or(0, |c| txs.len().saturating_sub(c as usize));
		display::txs(
			&g_args.account,
			res.height,
			validated || updater_running,
			&txs[first_tx..],
			include_status,
			dark_scheme,
		)?;

		// if given a particular transaction id or uuid, also get and display associated
		// inputs/outputs and messages
		let id = if args.id.is_some() {
			args.id
		} else if args.tx_slate_id.is_some() {
			if let Some(tx) = txs.iter().find(|t| t.tx_slate_id == args.tx_slate_id) {
				Some(tx.id)
			} else {
				println!("Could not find a transaction matching given txid.\n");
				None
			}
		} else {
			None
		};

		if id.is_some() {
			let (_, outputs) = api.retrieve_outputs(m, true, false, id)?;
			display::outputs(
				&g_args.account,
				res.height,
				validated || updater_running,
				outputs,
				dark_scheme,
			)?;
			// should only be one here, but just in case
			for tx in txs {
				display::payment_proof(&tx)?;
			}
		}

		Ok(())
	})?;
	Ok(())
}

/// Post
#[derive(Clone)]
pub struct PostArgs {
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub fluff: bool,
}

pub fn post<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: PostArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (slate, _ret_address) = parse_slatepack(
		owner_api,
		keychain_mask,
		args.input_file,
		args.input_slatepack_message,
	)?;

	let fluff = args.fluff;
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		api.post_tx(m, &slate, fluff)?;
		info!("Posted transaction");
		return Ok(());
	})?;
	Ok(())
}

/// Repost
pub struct RepostArgs {
	pub id: u32,
	pub dump_file: Option<String>,
	pub fluff: bool,
}

pub fn repost<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: RepostArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let stored_tx_slate = match api.get_stored_tx(m, Some(args.id), None)? {
			None => {
				error!(
					"Transaction with id {} does not have transaction data. Not reposting.",
					args.id
				);
				return Ok(());
			}
			Some(s) => s,
		};
		let (_, txs) = api.retrieve_txs(m, true, Some(args.id), None, None)?;
		match args.dump_file {
			None => {
				if txs[0].confirmed {
					error!(
						"Transaction with id {} is confirmed. Not reposting.",
						args.id
					);
					return Ok(());
				}
				if libwallet::sig_is_blank(
					&stored_tx_slate.tx.as_ref().unwrap().kernels()[0].excess_sig,
				) {
					error!("Transaction at {} has not been finalized.", args.id);
					return Ok(());
				}

				match api.post_tx(m, &stored_tx_slate, args.fluff) {
					Ok(_) => info!("Reposted transaction at {}", args.id),
					Err(e) => error!("Could not repost transaction at {}. Reason: {}", args.id, e),
				}
				return Ok(());
			}
			Some(f) => {
				let mut tx_file = File::create(f.clone())?;
				tx_file.write_all(
					json::to_string(&stored_tx_slate.tx.unwrap())
						.unwrap()
						.as_bytes(),
				)?;
				tx_file.sync_all()?;
				info!("Dumped transaction data for tx {} to {}", args.id, f);
				return Ok(());
			}
		}
	})?;
	Ok(())
}

/// Cancel
pub struct CancelArgs {
	pub tx_id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
	pub tx_id_string: String,
}

pub fn cancel<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: CancelArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.cancel_tx(m, args.tx_id, args.tx_slate_id);
		match result {
			Ok(_) => {
				info!("Transaction {} Cancelled", args.tx_id_string);
				Ok(())
			}
			Err(e) => {
				error!("TX Cancellation failed: {}", e);
				Err(e)
			}
		}
	})?;
	Ok(())
}

/// wallet check
pub struct CheckArgs {
	pub delete_unconfirmed: bool,
	pub start_height: Option<u64>,
	pub backwards_from_tip: Option<u64>,
}

pub fn scan<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: CheckArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let tip_height = api.node_height(m)?.height;
		let start_height = match args.backwards_from_tip {
			Some(b) => tip_height.saturating_sub(b),
			None => match args.start_height {
				Some(s) => s,
				None => 1,
			},
		};
		warn!("Starting output scan from height {} ...", start_height);
		let result = api.scan(m, Some(start_height), args.delete_unconfirmed);
		match result {
			Ok(_) => {
				warn!("Wallet check complete",);
				Ok(())
			}
			Err(e) => {
				error!("Wallet check failed: {}", e);
				Err(e)
			}
		}
	})?;
	Ok(())
}

/// Payment Proof Address
pub fn address<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	g_args: &GlobalArgs,
	keychain_mask: Option<&SecretKey>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		// Just address at derivation index 0 for now
		let address = api.get_slatepack_address(m, 0)?;
		println!();
		println!("Address for account - {}", g_args.account);
		println!("-------------------------------------");
		println!("{}", address);
		println!();
		Ok(())
	})?;
	Ok(())
}

/// Proof Export Args
pub struct ProofExportArgs {
	pub output_file: String,
	pub id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
}

pub fn proof_export<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ProofExportArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.retrieve_payment_proof(m, true, args.id, args.tx_slate_id);
		match result {
			Ok(p) => {
				// actually export proof
				let mut proof_file = File::create(args.output_file.clone())?;
				proof_file.write_all(json::to_string_pretty(&p).unwrap().as_bytes())?;
				proof_file.sync_all()?;
				warn!("Payment proof exported to {}", args.output_file);
				Ok(())
			}
			Err(e) => {
				error!("Proof export failed: {}", e);
				Err(e)
			}
		}
	})?;
	Ok(())
}

/// Proof Verify Args
pub struct ProofVerifyArgs {
	pub input_file: String,
}

pub fn proof_verify<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ProofVerifyArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let mut proof_f = match File::open(&args.input_file) {
			Ok(p) => p,
			Err(e) => {
				let msg = format!("{}", e);
				error!(
					"Unable to open payment proof file at {}: {}",
					args.input_file, e
				);
				return Err(libwallet::Error::PaymentProofParsing(msg));
			}
		};
		let mut proof = String::new();
		proof_f.read_to_string(&mut proof)?;
		// read
		let proof: PaymentProof = match json::from_str(&proof) {
			Ok(p) => p,
			Err(e) => {
				let msg = format!("{}", e);
				error!("Unable to parse payment proof file: {}", e);
				return Err(libwallet::Error::PaymentProofParsing(msg));
			}
		};
		let result = api.verify_payment_proof(m, &proof);
		match result {
			Ok((iam_sender, iam_recipient)) => {
				println!("Payment proof's signatures are valid.");
				if iam_sender {
					println!("The proof's sender address belongs to this wallet.");
				}
				if iam_recipient {
					println!("The proof's recipient address belongs to this wallet.");
				}
				if !iam_recipient && !iam_sender {
					println!(
						"Neither the proof's sender nor recipient address belongs to this wallet."
					);
				}
				Ok(())
			}
			Err(e) => {
				error!("Proof not valid: {}", e);
				Err(e)
			}
		}
	})?;
	Ok(())
}

// ---------------------------------------------------------------------------
// Multisig (experimental)
// ---------------------------------------------------------------------------

/// Multisig CLI arguments
pub struct MultisigArgs {
	pub subcommand: String,
	pub threshold: Option<usize>,
	pub total: Option<usize>,
	pub my_index: Option<usize>,
	pub shares_per_actor: Option<usize>,
	pub ceremony_id: Option<String>,
	pub local_sim: bool,
	pub file: Option<String>,
	pub out: Option<String>,
	pub out_dir: Option<String>,
	/// Ordered Slatepack addresses of all actors (multi-party roster). Enables
	/// encrypted share delivery; all parties must supply the same list.
	pub addresses: Option<Vec<String>>,
	/// Session id hex (WS4).
	pub session_id: Option<String>,
	/// Shared session tag string (WS4 create).
	pub session_tag: Option<String>,
	/// Coin number (CreateOutput).
	pub coin_number: Option<u64>,
	/// Coin value nanogrins (CreateOutput).
	pub coin_value: Option<u64>,
	/// Fee nanogrins (Spend).
	pub fee: Option<u64>,
	/// Input coins as "number:value".
	pub inputs: Option<Vec<String>>,
	/// Output coins as "number:value".
	pub outputs: Option<Vec<String>>,
	/// Abort reason.
	pub reason: Option<String>,
	/// Delete session file after abort.
	pub delete: bool,
	/// Optional label (allocate-coin).
	pub label: Option<String>,
	/// Commitment hex (recognize-utxo).
	pub commit_hex: Option<String>,
	/// Proof hex file path or hex string.
	pub proof: Option<String>,
	/// Block height (recognize-utxo).
	pub height: Option<u64>,
	/// Register if recognized.
	pub register: bool,
	/// Start PMMR index (scan-utxos).
	pub start_index: Option<u64>,
	/// End PMMR index (scan-utxos).
	pub end_index: Option<u64>,
	/// Max outputs per batch (scan-utxos).
	pub max_outputs: Option<u64>,
	/// Amount for select-utxos.
	pub amount: Option<u64>,
	/// Min confirmations for select-utxos.
	pub min_confirmations: Option<u64>,
	/// Target ceremony for plan-epoch-sweep.
	pub target_ceremony_id: Option<String>,
}

fn msig_wallet_data_dir<L, C, K>(owner_api: &Owner<L, C, K>) -> Result<String, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let tld = owner_api
		.get_top_level_directory()
		.map_err(Error::LibWallet)?;
	let dir = libwallet::multisig::wallet_data_dir(&tld);
	Ok(dir.display().to_string())
}

/// Derive the keychain-bound key used to encrypt pending DKG state at rest
/// (C-03). Opens the wallet so the pending file can never be read or written
/// without unlocking the wallet.
fn msig_pending_key<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
) -> Result<libwallet::multisig::PendingKey, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut key: Option<libwallet::multisig::PendingKey> = None;
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let mut w_lock = api.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let kc = w.keychain(m)?;
		key = Some(libwallet::multisig::derive_pending_key(&kc)?);
		Ok(())
	})?;
	key.ok_or_else(|| Error::GenericError("failed to derive multisig pending key".into()))
}

/// Multisig command dispatcher
pub fn multisig<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: MultisigArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	println!();
	println!("WARNING: Multisig is EXPERIMENTAL — do not use with real funds.");
	println!();

	match args.subcommand.as_str() {
		"list" => {
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let list = libwallet::multisig::list_ceremonies(&mut **w, m)?;
				if list.is_empty() {
					println!("No multisig ceremonies stored.");
				} else {
					println!(
						"{:<40} {:>5} {:>5} {:<16} {:>6}",
						"Ceremony ID", "M", "N", "Actor", "Shares"
					);
					println!("{}", "-".repeat(80));
					for s in list {
						println!(
							"{:<40} {:>5} {:>5} {:<16} {:>6}",
							s.ceremony_id, s.threshold, s.total_actors, s.my_label, s.num_shares
						);
					}
				}
				Ok(())
			})?;
		}
		"show" => {
			let cid = args
				.ceremony_id
				.ok_or_else(|| Error::ArgumentError("ceremony id required".into()))?;
			let uuid = Uuid::parse_str(&cid)
				.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
			let ceremony = libwallet::multisig::CeremonyId(uuid);
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let st = libwallet::multisig::get_state(&mut **w, m, &ceremony)?;
				println!("Ceremony:    {}", st.config.ceremony_id.0);
				println!(
					"Threshold:   {}-of-{}",
					st.config.params.threshold, st.config.params.total_actors
				);
				println!("Shares/actor:{}", st.config.params.shares_per_actor);
				println!(
					"My actor:    {} ({})",
					st.my_actor.label,
					st.my_actor.id.to_hex()
				);
				println!("Shares:      {}", st.shares.len());
				println!("Actors:");
				for (i, a) in st.config.actors.iter().enumerate() {
					println!("  [{}] {}", i, a.label);
				}
				println!(
					"Public poly coefficients: {}",
					st.config.public_poly.coefficients.len()
				);
				Ok(())
			})?;
		}
		"delete" => {
			let cid = args
				.ceremony_id
				.ok_or_else(|| Error::ArgumentError("ceremony id required".into()))?;
			let uuid = Uuid::parse_str(&cid)
				.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
			let ceremony = libwallet::multisig::CeremonyId(uuid);
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				libwallet::multisig::delete_ceremony(&mut **w, m, &ceremony)?;
				println!("Deleted ceremony {}", cid);
				Ok(())
			})?;
		}
		"init" => {
			let threshold = args.threshold.unwrap_or(2);
			let total = args.total.unwrap_or(3);
			let my_index = args.my_index.unwrap_or(0);
			if args.local_sim {
				controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
					let mut w_lock = api.wallet_inst.lock();
					let w = w_lock.lc_provider()?.wallet_inst()?;
					let st = libwallet::multisig::init_local_sim(
						&mut **w,
						m,
						threshold,
						total,
						my_index,
						args.shares_per_actor,
					)?;
					println!("Local-sim DKG complete.");
					println!("Ceremony: {}", st.config.ceremony_id.0);
					println!(
						"Threshold: {}-of-{} (shares/actor={})",
						st.config.params.threshold,
						st.config.params.total_actors,
						st.config.params.shares_per_actor
					);
					println!("This wallet is actor: {}", st.my_actor.label);
					Ok(())
				})?;
			} else {
				let wdata = msig_wallet_data_dir(owner_api)?;
				let key = msig_pending_key(owner_api, keychain_mask)?;
				let sign_key = owner_api
					.get_slatepack_secret_key(keychain_mask, 0)
					.map_err(Error::LibWallet)?;
				let out = args.out.unwrap_or_else(|| "msig_contrib.json".to_owned());
				let ceremony = match args.ceremony_id.as_ref() {
					Some(s) => {
						let u = Uuid::parse_str(s)
							.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
						Some(libwallet::multisig::CeremonyId(u))
					}
					None => None,
				};
				let pending = libwallet::multisig::dkg_start(
					&wdata,
					&key,
					Some(&sign_key),
					threshold,
					total,
					my_index,
					args.shares_per_actor,
					args.addresses.clone(),
					ceremony,
					&out,
				)
				.map_err(Error::LibWallet)?;
				println!("DKG started (multi-party).");
				println!("Ceremony: {}", pending.ceremony_id.0);
				println!("Your index: {}", pending.my_index);
				println!("Contribution written to: {}", out);
				println!();
				println!("Next steps for other actors:");
				println!(
					"  grin-wallet multisig init -m {} -n {} --index <i> --ceremony-id {} -o contrib_i.json",
					threshold, total, pending.ceremony_id.0
				);
				println!(
					"  grin-wallet multisig import-contrib -i contrib_j.json  (for each peer)"
				);
				println!("  grin-wallet multisig export-shares -d shares_out/");
				println!(
					"  grin-wallet multisig import-share -i share_file.json  (from each peer)"
				);
				println!("  grin-wallet multisig finalize");
			}
		}
		"pending" => {
			let wdata = msig_wallet_data_dir(owner_api)?;
			let key = msig_pending_key(owner_api, keychain_mask)?;
			match libwallet::multisig::load_pending(&wdata, &key).map_err(Error::LibWallet)? {
				None => println!("No pending DKG session."),
				Some(p) => {
					println!("Pending ceremony: {}", p.ceremony_id.0);
					println!(
						"Threshold: {}-of-{}",
						p.params.threshold, p.params.total_actors
					);
					println!("My index: {}", p.my_index);
					let got: usize = p.contributions.iter().filter(|c| c.is_some()).count();
					println!("Contributions: {}/{}", got, p.params.total_actors);
					let shares_got: usize =
						p.my_share_ys_hex.iter().filter(|s| s.is_some()).count();
					println!(
						"Imported share accumulators: {}/{}",
						shares_got, p.params.shares_per_actor
					);
				}
			}
		}
		"clear-pending" => {
			let wdata = msig_wallet_data_dir(owner_api)?;
			libwallet::multisig::clear_pending(&wdata).map_err(Error::LibWallet)?;
			println!("Pending DKG cleared.");
		}
		"import-contrib" => {
			let file = args
				.file
				.ok_or_else(|| Error::ArgumentError("--file required".into()))?;
			let wdata = msig_wallet_data_dir(owner_api)?;
			let key = msig_pending_key(owner_api, keychain_mask)?;
			let env = libwallet::multisig::read_envelope_file(&file).map_err(Error::LibWallet)?;
			let p = libwallet::multisig::dkg_import_contrib(&wdata, &key, &env)
				.map_err(Error::LibWallet)?;
			let got: usize = p.contributions.iter().filter(|c| c.is_some()).count();
			println!(
				"Imported contribution. Progress: {}/{}",
				got, p.params.total_actors
			);
		}
		"export-shares" => {
			let wdata = msig_wallet_data_dir(owner_api)?;
			let key = msig_pending_key(owner_api, keychain_mask)?;
			let sender_addr = owner_api
				.get_slatepack_address(keychain_mask, 0)
				.map_err(Error::LibWallet)?;
			let sign_key = owner_api
				.get_slatepack_secret_key(keychain_mask, 0)
				.map_err(Error::LibWallet)?;
			let out_dir = args.out_dir.unwrap_or_else(|| "msig_shares".to_owned());
			let paths = libwallet::multisig::dkg_export_shares(
				&wdata,
				&key,
				&sender_addr,
				&sign_key,
				&out_dir,
			)
			.map_err(Error::LibWallet)?;
			println!(
				"Wrote {} encrypted share file(s) under {}:",
				paths.len(),
				out_dir
			);
			for p in paths {
				println!("  {}", p);
			}
			println!(
				"Each file is an age-encrypted slatepack addressed to one actor; \
				 deliver it to that actor and import with `multisig import-share`."
			);
		}
		"import-share" => {
			let file = args
				.file
				.ok_or_else(|| Error::ArgumentError("--file required".into()))?;
			let wdata = msig_wallet_data_dir(owner_api)?;
			let key = msig_pending_key(owner_api, keychain_mask)?;
			let dec_key = owner_api
				.get_slatepack_secret_key(keychain_mask, 0)
				.map_err(Error::LibWallet)?;
			let env = libwallet::multisig::read_encrypted_share_file(&file, &dec_key)
				.map_err(Error::LibWallet)?;
			let p = libwallet::multisig::dkg_import_share(&wdata, &key, &env)
				.map_err(Error::LibWallet)?;
			let shares_got: usize = p.my_share_ys_hex.iter().filter(|s| s.is_some()).count();
			println!(
				"Imported share. Accumulators filled: {}/{}",
				shares_got, p.params.shares_per_actor
			);
		}
		"finalize" => {
			let wdata = msig_wallet_data_dir(owner_api)?;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let st = libwallet::multisig::dkg_finalize(&mut **w, m, &wdata)?;
				println!("DKG finalized and saved to wallet DB.");
				println!("Ceremony: {}", st.config.ceremony_id.0);
				println!("Actor: {}", st.my_actor.label);
				Ok(())
			})?;
		}
		"export-state" => {
			let cid = args
				.ceremony_id
				.ok_or_else(|| Error::ArgumentError("ceremony id required".into()))?;
			let out = args
				.out
				.ok_or_else(|| Error::ArgumentError("--out required".into()))?;
			let uuid = Uuid::parse_str(&cid)
				.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
			let ceremony = libwallet::multisig::CeremonyId(uuid);
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let st = libwallet::multisig::get_state(&mut **w, m, &ceremony)?;
				// AEAD-sealed under keychain-derived key (C-08) — not plaintext JSON.
				libwallet::multisig::export_state_sealed(&mut **w, m, &st, &out)?;
				println!(
					"Exported sealed multisig state (keychain-encrypted) to {}",
					out
				);
				Ok(())
			})?;
		}
		"import-state" => {
			let file = args
				.file
				.ok_or_else(|| Error::ArgumentError("--file required".into()))?;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let st = libwallet::multisig::import_state_sealed(&mut **w, m, &file)?;
				println!("Imported ceremony {}", st.config.ceremony_id.0);
				Ok(())
			})?;
		}
		"demo-tx" => {
			let threshold = args.threshold.unwrap_or(2) as u32;
			let total = args.total.unwrap_or(threshold.max(2) as usize) as u32;
			if threshold > total {
				return Err(Error::ArgumentError(
					"threshold cannot exceed total actors".into(),
				));
			}
			let fee = 1_000_000u32;
			let res = owner_api
				.multisig_demo_tx(threshold, total, fee)
				.map_err(Error::LibWallet)?;
			println!("E2E multisig demo OK ({}-of-{}).", res.threshold, res.total);
			println!("  Funded value:  {}", res.fund_value);
			println!("  Change value:  {} (fee {})", res.change_value, res.fee);
			println!("  Tx hash:       {}", res.tx_hash);
			println!("  Kernel excess: {}", res.kernel_excess);
			if let Some(out) = args.out.as_ref() {
				std::fs::write(out, &res.tx_hex)
					.map_err(|e| Error::GenericError(format!("write tx hex: {}", e)))?;
				println!("  Wrote tx hex to {}", out);
			}
			println!("  Transaction validates (rangeproofs + kernel sig + kernel sums).");
			let _ = keychain_mask;
		}
		"post-tx" => {
			let file = args
				.file
				.ok_or_else(|| Error::ArgumentError("--file required (tx hex)".into()))?;
			let fluff = true;
			let tx_hex = std::fs::read_to_string(&file)
				.map_err(|e| Error::GenericError(format!("read {}: {}", file, e)))?
				.trim()
				.to_owned();
			owner_api
				.multisig_post_tx(keychain_mask, tx_hex, fluff)
				.map_err(Error::LibWallet)?;
			println!("Posted transaction from {} (fluff={})", file, fluff);
		}
		"session-list" => {
			let wdata = msig_wallet_data_dir(owner_api)?;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let list = libwallet::multisig::session_list(&mut **w, m, &wdata)?;
				if list.is_empty() {
					println!("No durable sessions.");
				} else {
					println!(
						"{:<20} {:<14} {:<12} {:>5} {:>5}/{:<5}",
						"Session (hex..)", "Kind", "Phase", "Idx", "Have", "N"
					);
					println!("{}", "-".repeat(70));
					for s in list {
						let sid = if s.session_id_hex.len() > 16 {
							format!("{}…", &s.session_id_hex[..16])
						} else {
							s.session_id_hex.clone()
						};
						println!(
							"{:<20} {:<14} {:<12} {:>5} {:>5}/{:<5}",
							sid,
							format!("{:?}", s.kind),
							format!("{:?}", s.phase),
							s.my_index,
							s.collected,
							s.quorum_size
						);
					}
				}
				Ok(())
			})?;
		}
		"session-status" => {
			let sid = args
				.session_id
				.ok_or_else(|| Error::ArgumentError("--session required".into()))?;
			let wdata = msig_wallet_data_dir(owner_api)?;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let s = libwallet::multisig::session_status(&mut **w, m, &wdata, &sid)?;
				println!("Session:  {}", s.session_id_hex);
				println!("Kind:     {:?}", s.kind);
				println!("Phase:    {:?}", s.phase);
				println!("My index: {} / {}", s.my_index, s.quorum_size);
				println!("Collected this phase: {}/{}", s.collected, s.quorum_size);
				if let Some(r) = s.abort_reason {
					println!("Aborted:  {}", r);
				}
				Ok(())
			})?;
		}
		"session-create-output" => {
			let ceremony = args
				.ceremony_id
				.ok_or_else(|| Error::ArgumentError("--ceremony required".into()))?;
			let uuid = Uuid::parse_str(&ceremony)
				.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
			let coin_number = args
				.coin_number
				.ok_or_else(|| Error::ArgumentError("--coin-number required".into()))?;
			let coin_value = args
				.coin_value
				.ok_or_else(|| Error::ArgumentError("--coin-value required".into()))?;
			let tag = args
				.session_tag
				.clone()
				.unwrap_or_else(|| "create-output".into());
			let out = args
				.out
				.clone()
				.unwrap_or_else(|| "msig_sess_out.json".into());
			let wdata = msig_wallet_data_dir(owner_api)?;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let st = libwallet::multisig::session_create_output(
					&mut **w,
					m,
					&wdata,
					&libwallet::multisig::CeremonyId(uuid),
					coin_number,
					coin_value,
					&tag,
					&out,
					None,
				)?;
				println!("CreateOutput session started.");
				println!("  Session id: {}", st.session_id_hex);
				println!("  Phase:      {:?}", st.phase);
				println!("  Wrote:      {}", out);
				println!("  Exchange this envelope with quorum peers, then session-apply.");
				Ok(())
			})?;
		}
		"session-create-spend" => {
			let ceremony = args
				.ceremony_id
				.ok_or_else(|| Error::ArgumentError("--ceremony required".into()))?;
			let uuid = Uuid::parse_str(&ceremony)
				.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
			let parse_coin = |s: &str| -> Result<libwallet::multisig::CoinId, Error> {
				let parts: Vec<_> = s.split(':').collect();
				if parts.len() != 2 {
					return Err(Error::ArgumentError(
						"coin must be number:value".into(),
					));
				}
				let n = parts[0]
					.parse::<u64>()
					.map_err(|e| Error::ArgumentError(format!("coin number: {}", e)))?;
				let v = parts[1]
					.parse::<u64>()
					.map_err(|e| Error::ArgumentError(format!("coin value: {}", e)))?;
				Ok(libwallet::multisig::CoinId::new(n, v))
			};
			let inputs = args
				.inputs
				.clone()
				.unwrap_or_default()
				.iter()
				.map(|s| parse_coin(s))
				.collect::<Result<Vec<_>, _>>()?;
			let outputs = args
				.outputs
				.clone()
				.unwrap_or_default()
				.iter()
				.map(|s| parse_coin(s))
				.collect::<Result<Vec<_>, _>>()?;
			if inputs.is_empty() || outputs.is_empty() {
				return Err(Error::ArgumentError(
					"--input and --output required (number:value)".into(),
				));
			}
			let fee = args.fee.unwrap_or(1_000_000);
			let tag = args.session_tag.clone().unwrap_or_else(|| "spend".into());
			let out = args
				.out
				.clone()
				.unwrap_or_else(|| "msig_sess_out.json".into());
			let wdata = msig_wallet_data_dir(owner_api)?;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let st = libwallet::multisig::session_create_spend(
					&mut **w,
					m,
					&wdata,
					&libwallet::multisig::CeremonyId(uuid),
					inputs,
					outputs,
					fee,
					&tag,
					&out,
					None,
				)?;
				println!("Spend session started.");
				println!("  Session id: {}", st.session_id_hex);
				println!("  Phase:      {:?}", st.phase);
				println!("  Wrote:      {}", out);
				Ok(())
			})?;
		}
		"session-apply" => {
			let sid = args
				.session_id
				.ok_or_else(|| Error::ArgumentError("--session required".into()))?;
			let file = args
				.file
				.ok_or_else(|| Error::ArgumentError("--file required".into()))?;
			let out_dir = args
				.out_dir
				.clone()
				.unwrap_or_else(|| "msig_sess_out".into());
			let wdata = msig_wallet_data_dir(owner_api)?;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let (st, paths) =
					libwallet::multisig::session_apply(&mut **w, m, &wdata, &sid, &file, &out_dir)?;
				println!("Applied peer envelope.");
				println!("  Phase:     {:?}", st.phase);
				println!("  Collected: {}/{}", st.collected, st.quorum_size);
				if paths.is_empty() {
					println!("  No new outbound messages.");
				} else {
					println!("  Outbound:");
					for p in paths {
						println!("    {}", p);
					}
				}
				if st.phase == libwallet::multisig::SessionPhase::Complete {
					println!("  Session COMPLETE.");
				}
				Ok(())
			})?;
		}
		"session-abort" => {
			let sid = args
				.session_id
				.ok_or_else(|| Error::ArgumentError("--session required".into()))?;
			let reason = args
				.reason
				.clone()
				.unwrap_or_else(|| "user abort".into());
			let wdata = msig_wallet_data_dir(owner_api)?;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let st = libwallet::multisig::session_abort(
					&mut **w,
					m,
					&wdata,
					&sid,
					&reason,
					args.delete,
				)?;
				println!("Session aborted: {:?}", st.phase);
				if let Some(r) = st.abort_reason {
					println!("  Reason: {}", r);
				}
				Ok(())
			})?;
		}
		"list-utxos" => {
			let ceremony = args.ceremony_id.as_ref().map(|c| {
				Uuid::parse_str(c)
					.map(|u| libwallet::multisig::CeremonyId(u))
					.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))
			});
			let ceremony = match ceremony {
				Some(Ok(c)) => Some(c),
				Some(Err(e)) => return Err(e),
				None => None,
			};
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let list = libwallet::multisig::list_utxos(&mut **w, ceremony.as_ref())?;
				if list.is_empty() {
					println!("No multisig UTXOs tracked.");
				} else {
					println!(
						"{:<38} {:>8} {:>16} {:<12} {:>8}",
						"Ceremony", "Coin#", "Value", "Status", "Height"
					);
					println!("{}", "-".repeat(90));
					for u in list {
						println!(
							"{:<38} {:>8} {:>16} {:<12} {:>8}",
							u.ceremony_id.0,
							u.coin.number,
							u.coin.value,
							format!("{:?}", u.status),
							u.height
						);
					}
				}
				let _ = m;
				Ok(())
			})?;
		}
		"allocate-coin" => {
			let ceremony = args
				.ceremony_id
				.ok_or_else(|| Error::ArgumentError("--ceremony required".into()))?;
			let uuid = Uuid::parse_str(&ceremony)
				.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
			let value = args
				.coin_value
				.ok_or_else(|| Error::ArgumentError("--coin-value required".into()))?;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let u = libwallet::multisig::allocate_coin(
					&mut **w,
					m,
					&libwallet::multisig::CeremonyId(uuid),
					value,
					args.label.clone(),
				)?;
				println!("Reserved coin #{} value={}", u.coin.number, u.coin.value);
				println!("  Commit: {}", u.commit_hex);
				println!("  Status: {:?}", u.status);
				Ok(())
			})?;
		}
		"register-utxo" => {
			let ceremony = args
				.ceremony_id
				.ok_or_else(|| Error::ArgumentError("--ceremony required".into()))?;
			let uuid = Uuid::parse_str(&ceremony)
				.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
			let number = args
				.coin_number
				.ok_or_else(|| Error::ArgumentError("--coin-number required".into()))?;
			let value = args
				.coin_value
				.ok_or_else(|| Error::ArgumentError("--coin-value required".into()))?;
			let proof = if let Some(p) = args.proof.as_ref() {
				let s = std::fs::read_to_string(p)
					.unwrap_or_else(|_| p.clone())
					.trim()
					.to_owned();
				Some(
					libwallet::multisig::messages::proof_from_hex(&s)
						.map_err(|e| Error::LibWallet(e))?,
				)
			} else {
				None
			};
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let u = libwallet::multisig::register_utxo(
					&mut **w,
					m,
					&libwallet::multisig::CeremonyId(uuid),
					libwallet::multisig::CoinId::new(number, value),
					proof.as_ref(),
					args.session_id.clone(),
					libwallet::multisig::MultisigUtxoStatus::Unconfirmed,
				)?;
				println!(
					"Registered UTXO coin #{} value={} status={:?}",
					u.coin.number, u.coin.value, u.status
				);
				println!("  Commit: {}", u.commit_hex);
				Ok(())
			})?;
		}
		"recognize-utxo" => {
			let ceremony = args
				.ceremony_id
				.ok_or_else(|| Error::ArgumentError("--ceremony required".into()))?;
			let uuid = Uuid::parse_str(&ceremony)
				.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
			let commit = args
				.commit_hex
				.ok_or_else(|| Error::ArgumentError("--commit required".into()))?;
			let proof_path = args
				.proof
				.ok_or_else(|| Error::ArgumentError("--proof required".into()))?;
			let proof_hex = std::fs::read_to_string(&proof_path)
				.map_err(|e| Error::GenericError(format!("read proof: {}", e)))?
				.trim()
				.to_owned();
			let height = args.height.unwrap_or(0);
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let rec = libwallet::multisig::recognize_and_register(
					&mut **w,
					m,
					&libwallet::multisig::CeremonyId(uuid),
					&commit,
					&proof_hex,
					height,
					args.register,
				)?;
				match rec {
					Some(r) => {
						println!(
							"Recognized multisig coin #{} value={}",
							r.coin.number, r.coin.value
						);
						if args.register {
							println!("  Registered as Unspent at height {}", height);
						}
					}
					None => println!("Not recognized under this ceremony view key."),
				}
				Ok(())
			})?;
		}
		"scan-utxos" => {
			let ceremony = args
				.ceremony_id
				.ok_or_else(|| Error::ArgumentError("--ceremony required".into()))?;
			let uuid = Uuid::parse_str(&ceremony)
				.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
			let start = args.start_index.unwrap_or(1);
			let end = args.end_index;
			let max = args.max_outputs.unwrap_or(1000);
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let found = libwallet::multisig::scan_ceremony_utxos(
					&mut **w,
					m,
					&libwallet::multisig::CeremonyId(uuid),
					start,
					end,
					max,
				)?;
				if found.is_empty() {
					println!("No multisig outputs recognized in scanned range.");
				} else {
					println!("Recognized {} multisig UTXO(s):", found.len());
					for u in found {
						println!(
							"  coin #{} value={} status={:?} height={} mmr={:?}",
							u.coin.number, u.coin.value, u.status, u.height, u.mmr_index
						);
					}
				}
				Ok(())
			})?;
		}
		"refresh-utxos" => {
			let ceremony = args.ceremony_id.as_ref().map(|c| {
				Uuid::parse_str(c)
					.map(libwallet::multisig::CeremonyId)
					.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))
			});
			let ceremony = match ceremony {
				Some(Ok(c)) => Some(c),
				Some(Err(e)) => return Err(e),
				None => None,
			};
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let r = libwallet::multisig::refresh_multisig_utxos(
					&mut **w,
					m,
					ceremony.as_ref(),
				)?;
				println!(
					"Multisig refresh: examined={} confirmed={} marked_spent={}",
					r.examined, r.confirmed, r.marked_spent
				);
				Ok(())
			})?;
		}
		"select-utxos" => {
			let ceremony = args
				.ceremony_id
				.ok_or_else(|| Error::ArgumentError("--ceremony required".into()))?;
			let uuid = Uuid::parse_str(&ceremony)
				.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
			let amount = args
				.amount
				.ok_or_else(|| Error::ArgumentError("--amount required".into()))?;
			let min_conf = args.min_confirmations.unwrap_or(1);
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let height = w.w2n_client().get_chain_tip().map(|(h, _)| h).unwrap_or(0);
				let (selected, total) = libwallet::multisig::select_spendable_utxos(
					&mut **w,
					&libwallet::multisig::CeremonyId(uuid),
					amount,
					height,
					min_conf,
				)?;
				println!(
					"Selected {} coin(s), total {} (need {}) at height {}",
					selected.len(),
					total,
					amount,
					height
				);
				for u in selected {
					println!(
						"  coin #{} value={} height={}",
						u.coin.number, u.coin.value, u.height
					);
				}
				let _ = m;
				Ok(())
			})?;
		}
		"plan-epoch-sweep" => {
			let ceremony = args
				.ceremony_id
				.ok_or_else(|| Error::ArgumentError("--ceremony required (source)".into()))?;
			let src = Uuid::parse_str(&ceremony)
				.map_err(|e| Error::ArgumentError(format!("bad ceremony id: {}", e)))?;
			let tgt = match args.target_ceremony_id.as_ref() {
				Some(t) => Some(
					Uuid::parse_str(t)
						.map(libwallet::multisig::CeremonyId)
						.map_err(|e| Error::ArgumentError(format!("bad target ceremony: {}", e)))?,
				),
				None => None,
			};
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let plan = libwallet::multisig::plan_epoch_sweep(
					&mut **w,
					&libwallet::multisig::CeremonyId(src),
					tgt.as_ref(),
				)?;
				println!("Epoch sweep plan");
				println!("  Source: {}", plan.source_ceremony_id);
				if let Some(t) = &plan.target_ceremony_id {
					println!("  Target: {}", t);
				}
				println!("  Coins:  {} (total value {})", plan.coins.len(), plan.total_value);
				for c in &plan.coins {
					println!("    #{} value={}", c.number, c.value);
				}
				println!("  Note: {}", plan.note);
				let _ = m;
				Ok(())
			})?;
		}
		"expire-sessions" => {
			let wdata = msig_wallet_data_dir(owner_api)?;
			controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
				let mut w_lock = api.wallet_inst.lock();
				let w = w_lock.lc_provider()?.wallet_inst()?;
				let expired =
					libwallet::multisig::expire_stale_sessions(&mut **w, m, &wdata)?;
				if expired.is_empty() {
					println!("No expired multisig sessions.");
				} else {
					println!("Expired {} session(s):", expired.len());
					for st in expired {
						println!(
							"  {} phase={:?} reason={:?}",
							st.session_id_hex, st.phase, st.abort_reason
						);
					}
				}
				Ok(())
			})?;
		}
		other => {
			return Err(Error::ArgumentError(format!(
				"unknown multisig subcommand '{}'",
				other
			)));
		}
	}
	Ok(())
}
