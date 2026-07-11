#![no_main]
//! Fuzz target: MultisigEnvelope GMS1 magic + JSON payload parse (C-12).
use libfuzzer_sys::fuzz_target;

extern crate grin_wallet_libwallet;

use grin_wallet_libwallet::multisig::MultisigEnvelope;

fuzz_target!(|data: &[u8]| {
	if data.len() > 300_000 {
		return;
	}
	let _ = MultisigEnvelope::from_payload_bytes(data);
});
