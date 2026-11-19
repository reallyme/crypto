# reallyme-crypto-sha3

`reallyme-crypto-sha3` provides SHA3-224, SHA3-384, and SHA3-512 digest
wrappers for the ReallyMe Crypto workspace. SHA3-256 remains in
`reallyme-crypto-sha3-256` so callers that only need SHA3-256 can keep a
smaller dependency surface.

Digest wrappers clear their bytes on drop. Callers must clear exported copies.

## Test

```sh
cargo test -p reallyme-crypto-sha3 --features native
```
