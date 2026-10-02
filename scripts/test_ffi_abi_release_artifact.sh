#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -s)" in
  Darwin) readonly LIBRARY_PATH="${ROOT_DIR}/target/release-ffi/libcrypto_ffi.dylib" ;;
  Linux) readonly LIBRARY_PATH="${ROOT_DIR}/target/release-ffi/libcrypto_ffi.so" ;;
  *) echo "unsupported host for release FFI ABI test" >&2; exit 1 ;;
esac

cd "$ROOT_DIR"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-crypto-ffi-abi.XXXXXX")"
readonly TEMP_DIR
trap 'rm -rf "$TEMP_DIR"' EXIT

if env -u RUSTFLAGS cargo build --locked -p crypto-ffi --release >"${TEMP_DIR}/abort-build.log" 2>&1; then
  echo "abort-mode release FFI build unexpectedly succeeded" >&2
  exit 1
fi
if ! grep -Fq "crypto-ffi release artifacts require an unwind-capable panic strategy" \
    "${TEMP_DIR}/abort-build.log"; then
  echo "release FFI build failed before checking the unwind requirement" >&2
  exit 1
fi

cargo build --locked -p crypto-ffi --profile release-ffi
if [[ ! -f "$LIBRARY_PATH" ]]; then
  echo "release FFI artifact is missing" >&2
  exit 1
fi

if ! command -v clang >/dev/null 2>&1; then
  echo "clang is required for the C ABI sanitizer test" >&2
  exit 1
fi
clang -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"${ROOT_DIR}/crates/ffi/abi" "${ROOT_DIR}/scripts/ffi_abi_sanitizer.c" \
  -L"${ROOT_DIR}/target/release-ffi" -lcrypto_ffi \
  -Wl,-rpath,"${ROOT_DIR}/target/release-ffi" \
  -o "${TEMP_DIR}/ffi-abi-sanitizer"
"${TEMP_DIR}/ffi-abi-sanitizer"

echo "release FFI ABI artifact passed C sanitizer checks"
