# reallyme-crypto-p384

NIST P-384 ECDSA and ECDH with raw 48-byte private scalars,
SHA-384 message hashing and DER signatures. Key generation emits compressed
SEC1 public keys. Verification and agreement accept standard compressed or
uncompressed SEC1 points; compact and hybrid encodings are rejected.

Invalid signatures return typed errors. ECDH returns the fixed-width raw
x-coordinate; apply the protocol's KDF before using it as a key. Secret results
use zeroizing owners; clear any caller-owned copies.

Select `native` or `wasm` for the execution target.
