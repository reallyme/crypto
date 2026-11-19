# External test vectors

`provenance.json` records the source, pinned commit, license and SHA-256 of each
vendored file. Keep raw files, including upstream READMEs, byte-for-byte intact;
put normalization and policy differences in the test adapters.

Run the default external tests from the repository root:

```sh
cargo test -p external-vector-audit --no-default-features --features native
```

[External conformance vectors](../../docs/external-conformance-vectors.md) lists
executed suites, status-only corpora and the commands for ignored tests. A corpus
being present does not mean the library executes or passes every case in it.
