# crypto-rsa

RSA signature operations for ReallyMe Crypto.

This crate verifies RSASSA-PKCS1-v1_5 and RSASSA-PSS signatures over SHA-1,
SHA-256, SHA-384, and SHA-512. SHA-1 is present only for historical document
verification contexts such as X.509 and eMRTD passive authentication; it is not
exposed as a general-purpose hash primitive.

Public keys may be supplied as PKCS#1 `RSAPublicKey` DER or X.509 SPKI DER.
Multikey callers should use PKCS#1 DER for the `rsa-pub` multicodec.

RSA-PSS verification follows RFC 8017's `emBits = modBits - 1` rule. In
particular, a modulus where `modBits % 8 == 1` uses an encoded message one byte
shorter than the RSA signature.

`RsaSigningKey` imports unencrypted PKCS#8 DER for RSASSA-PKCS1-v1_5/SHA-256
(RS256). Signing accepts 2048..8192-bit keys, rejects inconsistent CRT fields,
and bounds the exponent and input DER before private arithmetic. Signing uses
OS-backed blinding and returns a typed error if entropy is unavailable. Only public SPKI, modulus and exponent can be exported.

Signing is available on Rust native and WASM lanes. Without either execution
lane it returns `PROVIDER_UNSUPPORTED_ALGORITHM`. Standalone protobuf import
and signing do not enable RSA signing in generic dispatch or SDK facades.
The general RSA verification limits retain historical compatibility independently
of the stronger signing profile. No encryption or decryption API is exposed.

`parse_rsa_pss_sha2_params` imports bounded, complete DER for SHA-2 PSS metadata
with MGF1. Protocols must still enforce their accepted hash/salt profile.

The PKCS#8 keys under `src/testdata` are public test fixtures and are never
appropriate for deployed identities.
