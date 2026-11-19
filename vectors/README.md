# Conformance vectors

`manifest.json` lists the positive and negative vector files and runtime lanes.
Most positive fixtures live directly in this directory; `positive/` and
`negative/` describe their required fields. `external/` contains pinned
third-party corpora indexed by `external/provenance.json`.

When adding a vector, record its algorithm, inputs, expected bytes or typed
error, and the lanes that execute it. Unsupported lanes need an explicit
unsupported-provider test. Register shared negative files under
`negative_vectors` and run:

```sh
node scripts/check_negative_vectors.mjs
```

Use the [conformance commands](../docs/conformance.md) to generate and verify
fixtures. Do not regenerate expected bytes to hide a failure. Corpus inventory
alone does not establish that every provider executed the cases.

Keys and seeds in these files are public test fixtures. Do not use them to
protect real data or add production secrets or personal data to the corpus.
