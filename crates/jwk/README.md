# reallyme-crypto-jwk

JWK envelope encoding and canonicalization for ReallyMe Crypto public keys.

Private-key members and malformed public-key encodings are rejected. See the
[JWK contract](https://github.com/reallyme/crypto/blob/main/docs/jwk.md) for
supported key shapes and canonicalization rules.

With the `proto` feature, deserialize untrusted JSON into
`proto_options::ProtectedJwk` or `proto_options::ProtectedJwks` to retain a
clearing owner through key validation and trailing-input rejection. Admission
uses generated guarded fields for individual keys and complete key sets. The
established `Jwk` and `Jwks` representations transfer their owned strings to
the caller; the protected owners provide borrowed access through `as_jwk()`
and `as_jwks()`.
