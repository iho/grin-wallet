#![no_main]
//! Fuzz target: MultisigEnvelope plain JSON parse + structural caps (C-12).
use libfuzzer_sys::fuzz_target;

extern crate grin_wallet_libwallet;

use grin_wallet_libwallet::multisig::MultisigEnvelope;

fuzz_target!(|data: &[u8]| {
	// Cap input size so the fuzzer exercises the parser, not OOM.
	if data.len() > 300_000 {
		return;
	}
	let s = match std::str::from_utf8(data) {
		Ok(s) => s,
		Err(_) => return,
	};
	let _ = MultisigEnvelope::from_json_str(s);
});
