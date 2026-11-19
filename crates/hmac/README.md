# crypto-hmac

Standalone HMAC authentication tags for ReallyMe Crypto.

This crate exposes HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 through typed key and tag
wrappers. It is intended for ratchet chain KDFs, transcript authentication, and
protocol code that needs raw HMAC rather than HKDF.

The public API rejects empty keys, caps key length at 4096 bytes, and verifies tags through the RustCrypto HMAC
implementation so same-length tag comparison is constant-time.

Select the `native` or `wasm` execution feature for your target.
