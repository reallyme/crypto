#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESOURCES_ROOT="${1:-${ROOT_DIR}/packages/kotlin/native}"

case "$(uname -s)" in
  Darwin)
    LIBRARY_PATH="${ROOT_DIR}/target/release-ffi/libcrypto_ffi.dylib"
    ;;
  Linux)
    LIBRARY_PATH="${ROOT_DIR}/target/release-ffi/libcrypto_ffi.so"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    LIBRARY_PATH="${ROOT_DIR}/target/release-ffi/crypto_ffi.dll"
    ;;
  *)
    printf 'unsupported operating system for Kotlin native resource staging\n' >&2
    exit 1
    ;;
esac

# Cargo gives encoded flags precedence over RUSTFLAGS. Remove that ambient
# injection route before selecting the audited profile and an empty flag set.
unset CARGO_ENCODED_RUSTFLAGS
RUSTFLAGS="" cargo build --locked -p crypto-ffi \
  --profile release-ffi
node "${ROOT_DIR}/scripts/stage_kotlin_native_resource.mjs" "${LIBRARY_PATH}" "${RESOURCES_ROOT}"
