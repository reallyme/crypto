#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR
readonly TARGET_DIR="${ROOT_DIR}/target"
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
readonly HOST_TARGET
case "$HOST_TARGET" in
  aarch64-apple-darwin|x86_64-apple-darwin|aarch64-unknown-linux-gnu|x86_64-unknown-linux-gnu) ;;
  *) echo "unsupported Rust host for release FFI ABI test" >&2; exit 1 ;;
esac
readonly LIBRARY_DIR="${TARGET_DIR}/${HOST_TARGET}/release-ffi"
case "$(uname -s)" in
  Darwin) readonly LIBRARY_PATH="${LIBRARY_DIR}/libcrypto_ffi.dylib" ;;
  Linux) readonly LIBRARY_PATH="${LIBRARY_DIR}/libcrypto_ffi.so" ;;
  *) echo "unsupported host for release FFI ABI test" >&2; exit 1 ;;
esac

cd "$ROOT_DIR"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-crypto-ffi-abi.XXXXXX")"
readonly TEMP_DIR
trap 'rm -rf "$TEMP_DIR"' EXIT

if env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS cargo check --locked -p crypto-ffi --release --target "$HOST_TARGET" --target-dir "$TARGET_DIR" >"${TEMP_DIR}/abort-build.log" 2>&1; then
  echo "abort-mode release FFI build unexpectedly succeeded" >&2
  exit 1
fi
if ! grep -Fq "crypto-ffi release artifacts require an unwind-capable panic strategy" \
    "${TEMP_DIR}/abort-build.log"; then
  echo "release FFI build failed before checking the unwind requirement" >&2
  exit 1
fi

cargo build --locked -p crypto-ffi --profile release-ffi --target "$HOST_TARGET" --target-dir "$TARGET_DIR"
if [[ ! -f "$LIBRARY_PATH" ]]; then
  echo "release FFI artifact is missing" >&2
  exit 1
fi

# Inspect the same production artifact exercised by the C harness. A separate
# build in another job could otherwise validate a different symbol surface.
if ! command -v nm >/dev/null 2>&1; then
  echo "nm is required for the production FFI symbol checks" >&2
  exit 1
fi
case "$(uname -s)" in
  Darwin) symbols="$(nm -gU "$LIBRARY_PATH")" ;;
  Linux) symbols="$(nm -D --defined-only "$LIBRARY_PATH")" ;;
esac
if ! grep -Eq '(^|[[:space:]])_?rm_crypto_ed25519_verify$' <<< "$symbols"; then
  echo "production FFI artifact has no expected Ed25519 export" >&2
  exit 1
fi
if grep -Eq '(^|[[:space:]])_?rm_crypto_(ml_kem_(512|768|1024)|x_wing_768)_encapsulate_derand$' <<< "$symbols"; then
  echo "conformance-only encapsulation symbols leaked into the production FFI artifact" >&2
  exit 1
fi

if ! command -v clang >/dev/null 2>&1; then
  echo "clang is required for the C ABI sanitizer test" >&2
  exit 1
fi
clang -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"${ROOT_DIR}/crates/ffi/abi" "${ROOT_DIR}/scripts/ffi_abi_sanitizer.c" \
  -L"${LIBRARY_DIR}" -lcrypto_ffi \
  -Wl,-rpath,"${LIBRARY_DIR}" \
  -o "${TEMP_DIR}/ffi-abi-sanitizer"
"${TEMP_DIR}/ffi-abi-sanitizer"

echo "release FFI ABI artifact passed C sanitizer checks"
