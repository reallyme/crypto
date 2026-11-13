# Prime-field encoding ownership and dependency delivery

The published `primefield` 0.14.0 implementation leaves named encoding and
decoding staging values without clearing owners. A retained outer key or
shared-secret owner cannot clear those discarded values. The repair in
[the candidate patch](../patches/primefield/0.14.0-encoding-ownership.patch)
guards those values without changing the field arithmetic or public API.
The canonical dependency remains the unmodified registry release. This document
describes an interim application override and the requirements for a registry
release; it does not declare the production finding closed.

## Reviewed source boundary

The patch applies to the published `primefield` **0.14.0** archive with SHA-256
`c555a6e4eb7d4e158fcb028c835c3b8642206ddc279b5c6b202ef9a8bdb592f4`.
Its source and candidate hashes are recorded in
[the patch manifest](../patches/primefield/manifest.json).
The original implementation and licensing are maintained by
[RustCrypto](https://github.com/RustCrypto/elliptic-curves/tree/master/primefield).

| Entry point | Ownership change |
| --- | --- |
| `MontyFieldElement::from_bytes` | Guard the padded byte array and decoded canonical integer; decode by borrowing the padding owner. |
| `MontyFieldElement::from_slice` | Guard the owned fixed-width representation before canonical decoding, including rejection. |
| `MontyFieldElement::to_bytes` | Guard the canonical integer, padded serialization and local result representation; transfer the caller-visible result with `mem::take`. |
| `PrimeField::from_repr` | Guard the owned input representation before delegating to borrowed decoding. |

The dependency manifest explicitly enables integer and array zeroization, with
defaults disabled. `Cargo.toml.orig` carries the equivalent source-manifest
changes. Four narrow deprecation allowances retain the existing public-modulus
metadata calls for compatibility with `crypto-bigint` 0.7.10 and 0.7.11. The
published normalized manifest's removed `from_iter_instead_of_collect` Clippy
lint is deleted; an upstream port must reconcile the workspace lint list too.

No modulus, scalar range, group operation, ladder, output width, byte order,
schema identifier or error contract changes. Returned byte arrays still have
their established by-value API: their recipient owns subsequent cleanup.
Borrowed inputs remain caller-owned. This is a source-level staging-ownership
repair, not whole-engine erasure, an after-drop memory experiment, or a promise
to erase every compiler/register copy. It does not establish a practical
disclosure or change cryptographic answers.

## Interim application integration

An application can use the reviewed repaired dependency while upstream review
and publication proceed. Its root manifest or root Cargo configuration must own
the override. Cargo only consults the root's `[patch]` table; putting it in a
published library does not make downstream applications inherit it. See
[Cargo's overriding-dependencies contract](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html#working-with-an-unpublished-minor-version).

For each new candidate:

1. Pin the crypto source commit and verify the patch SHA-256 from the manifest.
   Obtain the original registry archive and verify the archive SHA-256 above
   before extracting it into a new directory. Never modify a registry cache or
   an existing immutable build input.
2. Run `git apply --check --whitespace=error` against the extracted crate, then
   apply the patch. Verify all four resulting file hashes in the manifest.
   The patch targets the released archive, not an arbitrary upstream checkout.
3. Supply the repaired source at the application's dependency root, for example
   through the following Cargo configuration, where the absolute path identifies
   that application's verified candidate:

   ```toml
   [patch.crates-io]
   primefield = { path = "/absolute/path/to/verified/primefield-0.14.0" }
   ```

4. Resolve and retain that application's lockfile. Inspect
   `cargo tree --locked --offline -i primefield` and full `cargo metadata` to
   prove that every reached `primefield` resolves to the repaired source.
   Confirm the integer and array `zeroize` features. Record source and lockfile
   hashes alongside build evidence; the unchanged `0.14.0` version label alone
   does not identify the repair.
5. Run the applicable native/WASM known answers, negative and ownership tests
   against the exact candidate before accepting a build. Keep the original
   registry build and repaired candidate evidence separate. Preserve all
   protocol, curve-strength and trust decisions in the caller.

This is an explicit source override for applications that adopt it. It neither
changes crates.io's existing archive nor delivers a fix automatically to other
users of ReallyMe Crypto. It must not be represented as an upstream release.
The canonical crypto manifests and lockfiles contain no such override.

## Registry release path

As checked on **2026-11-13**, the registry's latest stable `primefield` is
**0.14.0**, without this repair. The preferred resolution is an upstream
compatible release carrying the reviewed ownership fix. **0.14.1 is a proposed
release target, not an existing or reserved fixed version**; the maintainer's
actual version and packaged source must replace that target before integration.

| Package set | Current exact version | Required release action |
| --- | --- | --- |
| `primefield` | 0.14.0 | Upstream publishes a reviewed compatible fixed release; proposed minimum 0.14.1. Record its actual archive checksum and compare the packaged source. |
| `primeorder`, `bp256`, `bp384`, `p256`, `p384`, `p521` | 0.14.0 each | Their existing compatible `primefield` requirements can resolve the upstream fixed release. No new release is required solely to rename a dependency; audit their resolved packaged graphs. |
| `wnaf` | 0.14.1 | Retain its compatible dependency identity; inspect it in the same reverse graph. |
| `crypto-bigint` / `hybrid-array` / `zeroize` | 0.7.10 / 0.4.15 / 1.9.1 in canonical crypto | The patch adds no required new release. Standalone compilation also checks `crypto-bigint` 0.7.11, `hybrid-array` 0.4.12 and `zeroize` 1.9.0. |
| ReallyMe Rust release set, including `reallyme-crypto`, `reallyme-crypto-rsa` and `reallyme-crypto-proto` | Unpublished 0.4.0 source | Publish the approved coordinated set only after dependency and runtime gates. Existing 0.3.17 packages stay unchanged. |

The [exact workspace package list](schema-contract-current-versions.csv) records
all source versions. `node scripts/publish_crates_in_order.mjs order` reports
the current 41 publishable packages in dependency order without publishing.
RSA's 0.4 API migration is part of that coordinated set; RSA does not become a
prime-field operation through this repair.

After the upstream archive is available:

1. Review the actual released diff and checksum. Require the fixed minimum in
   published manifests, not only in the workspace lockfile. A lockfile update
   alone permits another consumer to keep the older compatible dependency.
2. Apply that minimum to each independently consumable affected package and
   feature route. At minimum, review `reallyme-crypto`, its standalone P-256,
   P-384 and P-521 leaves, and `reallyme-crypto-hpke`. Activate any direct
   version-floor dependency only with the corresponding arithmetic providers;
   metadata-only and unrelated KEM features must remain narrow. HPKE review
   includes its three NIST KEMs and P-256/P-384 hybrid KEM routes. A floor in the
   umbrella package does not constrain a separately consumed leaf.
3. Regenerate both normal and fuzz lockfiles with the exact reviewed release.
   Check every supported narrow graph for a retained vulnerable registry copy,
   unexpected Git/path source, accidental provider activation or new platform
   dependency. Reverse reachability identifies review scope; it does not prove
   that every reached package serializes a secret through this function.
4. Verify the packaged ReallyMe manifests and archives in dependency order,
   using clean registry consumer projects without overrides. Execute the
   required runtime, negative, ownership and conformance gates there. Native,
   WASM and mobile compilation cannot substitute for those runs.
5. Obtain the repository's separate authorization for the exact remote and
   package operations. Publish the approved set, then verify actual registry
   archives and consumer resolution before declaring delivery complete.

If an upstream release cannot arrive in time, a maintained published fork is a
separate release decision. Renaming only the root's direct `primefield`
dependency would leave original transitive copies. The reverse graph includes
`primeorder`, both upstream Brainpool crates, three NIST crates and `wnaf`, with
additional consumers such as HPKE. A fork plan must migrate and validate every
required reverse dependency and trait identity while retaining license and
source provenance. It requires its own package ownership and publication
approval. No fork package, public repository or alternate arithmetic engine is
created by this candidate.

## Candidate validation

The validation manifest distinguishes the exact original archive, repaired
source and canonical consumer checkpoint. The retained regression sources cover
all low sixteen-bit values in padded P-256 storage in both byte orders,
canonical boundaries, invalid lengths and explicit clearing-owner requirements.
They do not perform unsafe reads after an allocation is released.

Compilation and Clippy results are source evidence only. Runtime tests,
application/device execution, upstream acceptance and publication remain
separate requirements. The accepted production dependency limitation in the
[reader matrix](reader-primitive-compatibility.md#ownership-and-delivery-limits)
remains open until a consumer uses the reviewed repair or fixed release; a
candidate artifact alone does not change the dependency being built.

| Candidate check | Result |
| --- | --- |
| Field all-target native and WASM compilation, `crypto-bigint` 0.7.10 and 0.7.11 | Passed with warnings denied |
| Field all-target Rust 1.96.0 compilation, `crypto-bigint` 0.7.10 | Passed with warnings denied |
| Field all-target/all-feature Clippy, both integer versions | Passed with warnings denied and no lint-suppression command flags |
| Canonical 0.4.0 group/adapter native and WASM all-target compilation | Passed in an isolated source copy with the explicit repaired-source override |
| Canonical group/adapter native Clippy | Passed with warnings denied under the same override |
| Narrow Base/P-256/HKDF-SHA256/AES-128-GCM HPKE native and WASM all-target compilation | Passed under the same override |
| Formatting and exact-baseline patch application | Passed |
| Runtime regressions and mobile/device execution for this candidate | Unexecuted; remain separate release gates |
