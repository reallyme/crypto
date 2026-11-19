# Build and CI checks

`CI / Required CI` checks the candidate SHA. Its policy lane always runs;
code, protobuf and fuzz-build jobs are selected by changed paths.

Run the pinned repository checker from the root:

```sh
node scripts/run_pinned_release_readiness.mjs
```

Use [conformance.md](conformance.md#release-checks) for the Rust and SDK
commands. Protobuf changes also require the
[generation checks](protobuf.md#generation).

To test locally built Rust code through Swift:

```sh
cargo build --locked -p crypto-ffi
touch .reallyme-crypto-runtime-ffi
REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI=1 REALLYME_CRYPTO_FFI_LIBRARY_PATH="$PWD/target/debug/libcrypto_ffi.dylib" node scripts/run_pinned_release_readiness.mjs
```

Formal Verification runs only by manual dispatch. Required CI and package
preflight receipts do not attest to it. Follow the
[formal release checklist](../RELEASE_CHECKLIST.md#formal-verification-before-publication)
for the exact release commit.

Package preflights require Required CI and Dependency Security for the source
SHA. If a documentation-only push skips Dependency Security, dispatch that
workflow from the same commit before starting preflight.

## Local file protection

Install the repository's pre-commit and pre-push checks after cloning:

```sh
python3 -B scripts/install_repository_hooks.py
python3 -B scripts/check_repository_privacy.py --index
```

The installer refuses to replace active hooks; integrate the checks into the
existing hook chain if needed. Excluded files must remain local, including files
added with `git add -f`. Checks preserve local contents. To untrack an excluded
file, preserve its local copy and use `git rm --cached -- PATH`.

Publishing checks inspect archives with `scripts/check_release_privacy.py`.
The absolute ignore policy currently rejects npm's `dist/` layout and Android
AAR metadata under `META-INF/com/android/build/`. Resolve these packaging
conflicts before release. Hooks can be disabled and CI runs after upload;
repository hosting controls are also required to prevent public uploads.
