# External vector tests

Test public Rust APIs against the raw upstream corpora in `vectors/external`:

```sh
cargo test -p external-vector-audit --no-default-features --features native
```

RFC 9180 and PQ HPKE adapters run with the ordinary native workspace tests.
For slow CCTV sweeps:

```sh
node scripts/run_external_cctv_deep_audit.mjs
```

See [external conformance vectors](../../docs/external-conformance-vectors.md)
for ignored adapters, coverage limits and corpus updates. DER and SEC1 adapters
use the separate reference encoder in [`src/refenc.rs`](src/refenc.rs).
