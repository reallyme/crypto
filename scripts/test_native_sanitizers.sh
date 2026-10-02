#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly TOOLCHAIN="${REALLYME_CRYPTO_SANITIZER_TOOLCHAIN:-nightly-2026-07-01}"
readonly TARGET="${REALLYME_CRYPTO_SANITIZER_TARGET:-$(rustc +"$TOOLCHAIN" -vV | sed -n 's/^host: //p')}"
readonly TEST_ARGS=(
  test --locked -p crypto-ffi --lib --tests --target "$TARGET"
)

RUSTFLAGS="-Zsanitizer=address" cargo +"$TOOLCHAIN" "${TEST_ARGS[@]}"

# This pinned nightly does not offer -Zsanitizer=undefined. Its checked-UB
# flags cover the Rust boundary while the C ABI harness uses Clang UBSan.
RUSTFLAGS="-Zub-checks=yes -Zextra-const-ub-checks=yes" cargo +"$TOOLCHAIN" "${TEST_ARGS[@]}"
