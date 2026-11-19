# reallyme-crypto-sha2

`reallyme-crypto-sha2` provides SHA-384 and SHA-512 digest wrappers for the
ReallyMe Crypto workspace. SHA-256 remains in `reallyme-crypto-sha2-256` so
callers that only need SHA-256 can keep a smaller dependency surface.

Digest wrappers clear their bytes on drop. Callers must clear exported copies.

## Test

```sh
cargo test -p reallyme-crypto-sha2 --features native
```
