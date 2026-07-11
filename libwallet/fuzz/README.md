# Multisig envelope fuzz targets (WS5)

Fuzz the experimental multisig wire parser with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```bash
cargo install cargo-fuzz
cd libwallet/fuzz
cargo +nightly fuzz run multisig_envelope_json
cargo +nightly fuzz run multisig_envelope_payload
```

Targets exercise `MultisigEnvelope::from_json_str` and `from_payload_bytes`
(size caps, structural DoS limits, version checks). They must never panic on
arbitrary input.
