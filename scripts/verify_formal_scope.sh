#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

# The workflow checks the candidate SHA before and after this script. Keep each
# matrix scope self-contained so any unfinished proof fails its own job.
kani_args=(-Z unstable-options --harness-timeout 15m --jobs 2 --output-format terse)
export CARGO_NET_OFFLINE=true

case "${FORMAL_SCOPE:-}" in
  operation-wire)
    cargo kani -p reallyme-crypto-proto --features generated "${kani_args[@]}"
    CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false \
      cargo kani -p reallyme-crypto --features operation-response --lib -Z stubbing "${kani_args[@]}"
    ;;
  restricted-dispatch)
    export CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false
    cargo kani -p reallyme-crypto-dispatch --no-default-features --features proto,native,ed25519 \
      --lib -Z stubbing "${kani_args[@]}"
    cargo kani -p reallyme-crypto --no-default-features --features operation-response,native,ed25519 \
      --lib -Z stubbing "${kani_args[@]}"
    cargo test --locked -p reallyme-crypto --no-default-features --features operation-response,native,ed25519 \
      --test restricted_operation_dispatch_tests
    ;;
  plaintext-release)
    cargo kani -p reallyme-crypto-core -Z stubbing "${kani_args[@]}"
    cargo kani -p crypto-ffi --lib -Z stubbing "${kani_args[@]}"
    cargo kani -p reallyme-crypto-wasm --lib "${kani_args[@]}"
    ;;
  hpke-dispatch)
    cargo kani -p reallyme-crypto-hpke --no-default-features --features native "${kani_args[@]}"
    cargo kani -p reallyme-crypto-hpke --no-default-features \
      --features base-p256-aes128gcm,aead-export-only "${kani_args[@]}"
    ;;
  hpke-state)
    python3 -B formal/hpke/verify_test.py
    python3 formal/hpke/verify.py
    ;;
  hpke-vectors)
    timeout 10m python3 -B formal/hpke/check_schedule_vectors.py
    ;;
  provider-profiles)
    export CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false
    cargo kani -p reallyme-crypto-dispatch --no-default-features --features proto,wasm,secp256k1,ml-kem-768 \
      --lib "${kani_args[@]}"
    cargo kani -p reallyme-crypto-dispatch --no-default-features --features proto,native,ml-dsa-65,ml-kem-768 \
      --lib -Z stubbing "${kani_args[@]}"
    ;;
  ml-kem-encoding)
    # Select cmov's portable implementation so Kani can verify its behavior.
    RUSTFLAGS="--cfg miri" python3 -B formal/hpke/verify.py module-lattice
    ;;
  ml-kem-key-admission)
    cargo kani -p reallyme-crypto-ml-kem-512 -p reallyme-crypto-ml-kem-768 -p reallyme-crypto-ml-kem-1024 \
      --no-default-features --features native --lib --harness key_import_and_encapsulation_share_the_fail_closed_gate \
      -Z stubbing "${kani_args[@]}"
    cargo test --locked -p reallyme-crypto --no-default-features --features native,ml-kem-512,ml-kem-768,ml-kem-1024 \
      --test ml_kem_public_key_validation_tests
    ;;
  x-wing-combiner)
    python3 -B formal/hpke/verify.py x-wing
    ;;
  ecdsa)
    CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false CARGO_PROFILE_DEV_OPT_LEVEL=1 RUSTFLAGS="--cfg miri" \
      cargo kani -p reallyme-crypto-p256 -p reallyme-crypto-secp256k1 \
        --no-default-features --features native --lib "${kani_args[@]}"
    ;;
  key-agreement)
    cargo kani -p reallyme-crypto-x25519 -p reallyme-crypto-x448 --no-default-features --features native \
      --lib -Z stubbing "${kani_args[@]}"
    ;;
  x25519-backend)
    python3 -B formal/hpke/verify.py x25519-dalek
    ;;
  aes-key-wrap)
    cargo kani -p reallyme-crypto-aes-kw --no-default-features --features native --lib "${kani_args[@]}"
    python3 -B formal/hpke/verify.py aes-kw
    ;;
  keccak)
    python3 -B formal/hpke/verify.py keccak
    ;;
  *)
    printf 'Expected a recognized formal verification scope.\n' >&2
    exit 2
    ;;
esac
