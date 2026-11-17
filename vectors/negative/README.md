# Negative Vectors

Negative vectors contain malformed, tampered, downgraded, unsupported,
wrong-context, or boundary inputs that must fail closed.

Each vector must identify:

- primitive or backend under test;
- exact tamper or invalid condition;
- expected typed error variant;
- whether state must remain unchanged after failure;
- runtime lanes where the failure is executed or explicitly guarded.

The shared `p256.json`, `p384.json`, and `p521.json` files also contain exact
negative encoding bytes alongside their valid signatures and public keys.
`signature_der_nonminimal_sequence_length`,
`signature_der_indefinite_sequence_length`, and
`signature_der_nonminimal_integer_length` preserve the ECDSA scalars but
violate canonical DER. `public_key_hybrid_even` and `public_key_hybrid_odd`
preserve the uncompressed point coordinates with forbidden SEC1 tags `0x06`
and `0x07`. Rust, Swift, Kotlin, and TypeScript package tests reject these
fixtures through typed errors; valid compressed keys remain accepted.
