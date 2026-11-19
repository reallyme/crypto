# crypto-conformance-vectors

Generate and validate the shared fixtures listed in
[`vectors/manifest.json`](../../vectors/manifest.json). Each platform runs the
subset supported by its selected provider.

```sh
cargo run -p crypto-conformance-vectors --bin gen_vectors
cargo nextest run -p crypto-conformance-vectors
npm run --prefix crates/conformance verify:ts-native
swift test --package-path crates/conformance/platform/swift
(cd crates/conformance/platform/kotlin && ./gradlew test --rerun-tasks)
```

The generator writes the root `vectors/` directory. Regenerate only for an
intentional contract change and review the diff. Independent post-quantum checks
use the pinned noble package.

See [conformance](../../docs/conformance.md) for release commands and
[JWK/multikey](../../docs/jwk.md) for supported public-key mappings, including
algorithms without assigned multicodec identifiers.
