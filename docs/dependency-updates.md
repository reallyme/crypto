# Updating dependencies

Update manifests and lockfiles together. Keep GitHub Actions pinned to immutable
revisions and review cryptographic output, errors and provider changes against
the [conformance checks](conformance.md). Do not regenerate vectors to hide an
unexpected output change.

KMAC's `sha3-kmac-state` alias must resolve to the SHA-3 version used by
`sha3-kmac`, with `zeroize` enabled. Enabling that feature on a different major
version does not clear the keyed sponge. Retain `zeroize` on `aes-gcm-siv`,
`polyval` and `poly1305` in each supported dependency graph.

```sh
cargo update
cargo outdated
cargo audit
node scripts/check_kmac_zeroization.mjs
node scripts/check_aead_zeroization.mjs
bash scripts/audit_committed_lockfiles.sh
```

Source manifests require Codec 0.4.4, while the checked-in lockfiles and Maven
provenance still describe earlier releases. Complete dependency resolution and
refresh verified artifacts before building or publishing this source version.
Do not substitute invented checksums or silently use an older Codec release.

Release policy files have SHA-256 pins in
`scripts/run_pinned_release_readiness.mjs`. After reviewing a checker edit,
update its pin with:

```sh
node scripts/run_pinned_release_readiness.mjs --refresh-checker-pin
node scripts/run_pinned_release_readiness.mjs --check-pins
```

Changes to pinned dependencies or the vendored core require individual digest
updates after review. CI cannot refresh its own checker pin.
