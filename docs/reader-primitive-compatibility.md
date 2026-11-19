# Reader primitive APIs

These Rust APIs provide cryptographic building blocks for document readers.
They do not implement certificate policy, revocation, replay protection,
transcript encoding or a complete ISO/IEC 18013-5 reader.

## Selecting features

Disable defaults when selecting a narrow set of primitives:

```toml
reallyme-crypto = { version = "0.4.3", default-features = false, features = [
  "brainpool", "ed448", "key-identifier-sha1", "operation-response"
] }
```

`operation-response` enables schema adapters for selected primitives; it does
not enable every algorithm. The explicit ECDSA and Ed448 implementations are
portable across native and WASM targets. Other leaves may also require their
`native` or `wasm` feature. See each crate's README.

| Operation | Rust API | Feature |
| --- | --- | --- |
| NIST and Brainpool ECDSA/ECDH | `ecdsa_explicit::{EcdsaKey, verify, validate_public_key}` | `ecdsa-explicit`; `brainpool` adds Brainpool curves |
| Ordinary Ed448 | `ed448::{Ed448Key, verify}` | `ed448` |
| X448 agreement | `crypto_x448::{X448PrivateKey, X448PublicKey, derive_x448_shared_secret}` | X448 leaf `native` or `wasm` |
| Subject key identifier, RFC 5280 method (1) | `key_identifier::subject_key_identifier_sha1` | `key-identifier-sha1` |
| Supplied-base group operations | `prime_groups::{PrimeGroup, GroupScalar, GroupElement}` | `prime-groups` |
| RSA public representative | `crypto_rsa::rsa_public_representatives` | RSA leaf |
| Single-record P-256 Base HPKE | `crypto_hpke::base_p256::{P256RecipientKey, seal, open}` | HPKE leaf `base-p256-aes128gcm` |

Add the selected leaf's `proto` feature, or the root's `operation-response`,
for its standalone schema adapter. A schema identifier does not imply a generic
executable operation or an SDK route.

## Curves, hashes and signatures

| Curve | Scalar/shared-secret bytes | Uncompressed SEC1 public bytes |
| --- | --- | --- |
| P-256 | 32 | 65 |
| P-384 | 48 | 97 |
| P-521 | 66 | 133 |
| brainpoolP256r1 | 32 | 65 |
| brainpoolP320r1 | 40 | 81 |
| brainpoolP384r1 | 48 | 97 |
| brainpoolP512r1 | 64 | 129 |

The explicit ECDSA API takes a message or an exact-length prehash and an
explicit SHA-256, SHA-384 or SHA-512 choice. Select the hash from the validated
protocol or certificate algorithm; do not infer it from curve size. Raw ECDH
returns the fixed-width big-endian x-coordinate, including leading zeros.
X25519 and X448 use their RFC 7748 little-endian encodings.

`EcdsaEncoding::Der` requires canonical DER and nonzero scalars below the curve
order. `FixedWidth` is full-width big-endian `r || s`. No format is inferred
from length. `der_to_fixed` and `fixed_to_der` preserve high-S values. Explicit
certificate verification accepts valid high-S signatures; the separate low-S
signature APIs retain their stricter policy.

Ordinary Ed448 uses an empty context and no external prehash. Ed448ph and
contextual variants are not accepted by this API.

The legacy subject-key-identifier function hashes the subjectPublicKey BIT
STRING payload supplied by the caller. Remove ASN.1 framing first. It preserves
the SEC1 prefix, so compressed and uncompressed points have different identifiers.
SHA-1 here is a legacy identifier operation, not a signature recommendation.

RSA representatives return `s^e mod n` and its modulus complement. They do not
validate padding or a signature scheme. Use the complete RSA verifier when
that is the operation your protocol requires.

## Bounded HPKE contract

`base-p256-aes128gcm` selects KEM `0x0010`, KDF `0x0001` and AEAD `0x0001`.
Each call creates a fresh single-record Base context with empty AAD. Pass the
protocol's exact `info` bytes; transcript parsing, tags and role binding belong
to the caller.

Recipient import takes a valid 32-byte big-endian scalar. Public keys and
encapsulations must be 65-byte uncompressed SEC1 encodings starting with `0x04`.
`P256BaseSealed` returns the encapsulation separately from ciphertext, which
includes the trailing 16-byte authentication tag.

Limits are 65,530 bytes of `info`, 16,777,216 bytes of plaintext and 16,777,232
bytes of ciphertext. Successful open returns a clearing `P256BasePlaintext`
owner with borrowed byte access. Base mode does not authenticate the sender.
Use the generic HPKE API for other suites, modes or nonempty AAD.

## Optional native providers

`brainpool-openssl` and `ed448-openssl` are excluded from defaults. Native builds
require a target-compatible OpenSSL installation. The runtime policy accepts
3.5.9 or later within 3.5, 4.0.3 or later within 4.0, and 4.1.x. Other families
are rejected. See [`native_provider.rs`](../crates/crypto/src/native_provider.rs).
Selecting a native provider does not permit runtime fallback.

For an iOS cross-build using the pinned provider builder:

```sh
IPHONEOS_DEPLOYMENT_TARGET=16.0 cargo run --locked -p optional-provider-build -- --target aarch64-apple-ios --out-dir /tmp/crypto-provider-ios
IPHONEOS_DEPLOYMENT_TARGET=16.0 OPENSSL_DIR=/tmp/crypto-provider-ios/install OPENSSL_STATIC=1 cargo check --locked -p reallyme-crypto --target aarch64-apple-ios --no-default-features --features brainpool-openssl,ed448-openssl,key-identifier-sha1
```

Use the application's deployment target and configure the matching compiler/SDK.
WASM uses the portable implementation; the native dependency is target-excluded.

## Ownership and delivery limits

`EcdsaKey`, `Ed448Key` and `P256RecipientKey` clear on drop and expose no private
export. Clear caller-owned input, exported bytes and serialized requests yourself.
Platform SDK arrays and borrowed views have different ownership guarantees.

Portable Brainpool ECDH has a known unguarded coordinate-serialization buffer in
`primefield` 0.14.0. The published dependency graph does not include the candidate
repair. Read [the memory limitation](../SECURITY_MEMORY_MODEL.md#known-portable-brainpool-limitation)
before choosing that path for a deployment requiring complete secret-buffer
cleanup.

## Validation

Run the selected profiles with `cargo check --locked` and the matching native
or WASM tests. The [conformance commands](conformance.md#release-checks) cover
the release checks. Compilation alone does not establish target runtime support
or an independent cryptographic audit.
