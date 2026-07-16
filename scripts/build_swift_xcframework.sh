#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build/swift"
HEADERS_DIR="${BUILD_DIR}/headers"
FRAMEWORK_DIR="${BUILD_DIR}/ReallyMeCryptoFFI.xcframework"
ZIP_PATH="${BUILD_DIR}/ReallyMeCryptoFFI.xcframework.zip"
CHECKSUM_PATH="${BUILD_DIR}/ReallyMeCryptoFFI.xcframework.checksum"

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required tool not found: %s\n' "$1" >&2
    exit 1
  fi
}

build_target() {
  local target="$1"
  rustup target add "${target}"
  RUSTFLAGS="${RUSTFLAGS:-} -C panic=unwind" \
    cargo build -p crypto-ffi --release --target "${target}"
}

copy_or_lipo() {
  local output="$1"
  shift
  if [ "$#" -eq 1 ]; then
    cp "$1" "${output}"
  else
    lipo -create "$@" -output "${output}"
  fi
}

install_modulemaps() {
  local slice
  for slice in "${FRAMEWORK_DIR}"/*; do
    if [ -d "${slice}/Headers" ]; then
      mkdir -p "${slice}/Modules"
      cat >"${slice}/Modules/module.modulemap" <<'MODULEMAP'
module ReallyMeCryptoFFI {
  header "reallyme_crypto_ffi.h"
  export *
}
MODULEMAP
    fi
  done
}

verify_xcframework_layout() {
  local header_modulemap
  header_modulemap="$(find "${FRAMEWORK_DIR}" -path '*/Headers/module.modulemap' -print -quit)"
  if [ -n "${header_modulemap}" ]; then
    printf 'invalid SwiftPM artifact layout: module map must not be exported from Headers: %s\n' \
      "${header_modulemap}" >&2
    exit 1
  fi
}

require_tool cargo
require_tool rustup
require_tool xcodebuild
require_tool lipo
require_tool find
require_tool sort
require_tool swift
require_tool touch
require_tool zip

rm -rf "${BUILD_DIR}"
mkdir -p "${HEADERS_DIR}" "${BUILD_DIR}/libs"
cp "${ROOT_DIR}/crates/crypto/ffi/abi/reallyme_crypto_ffi.h" \
  "${HEADERS_DIR}/reallyme_crypto_ffi.h"

build_target aarch64-apple-darwin
build_target x86_64-apple-darwin
build_target aarch64-apple-ios
build_target aarch64-apple-ios-sim
build_target x86_64-apple-ios

copy_or_lipo \
  "${BUILD_DIR}/libs/libcrypto_ffi_macos.a" \
  "${ROOT_DIR}/target/aarch64-apple-darwin/release/libcrypto_ffi.a" \
  "${ROOT_DIR}/target/x86_64-apple-darwin/release/libcrypto_ffi.a"

copy_or_lipo \
  "${BUILD_DIR}/libs/libcrypto_ffi_ios.a" \
  "${ROOT_DIR}/target/aarch64-apple-ios/release/libcrypto_ffi.a"

copy_or_lipo \
  "${BUILD_DIR}/libs/libcrypto_ffi_ios_simulator.a" \
  "${ROOT_DIR}/target/aarch64-apple-ios-sim/release/libcrypto_ffi.a" \
  "${ROOT_DIR}/target/x86_64-apple-ios/release/libcrypto_ffi.a"

xcodebuild -create-xcframework \
  -library "${BUILD_DIR}/libs/libcrypto_ffi_macos.a" -headers "${HEADERS_DIR}" \
  -library "${BUILD_DIR}/libs/libcrypto_ffi_ios.a" -headers "${HEADERS_DIR}" \
  -library "${BUILD_DIR}/libs/libcrypto_ffi_ios_simulator.a" -headers "${HEADERS_DIR}" \
  -output "${FRAMEWORK_DIR}"

install_modulemaps
verify_xcframework_layout

rm -f "${ZIP_PATH}" "${CHECKSUM_PATH}"
(
  cd "${BUILD_DIR}"
  # SwiftPM checksums cover the archive bytes, so normalize metadata and entry
  # ordering to make independent release builds produce the same artifact.
  TZ=UTC find "ReallyMeCryptoFFI.xcframework" -exec touch -t 198001010000 {} +
  find "ReallyMeCryptoFFI.xcframework" -print \
    | LC_ALL=C sort \
    | zip -X -q "ReallyMeCryptoFFI.xcframework.zip" -@
)
swift package compute-checksum "${ZIP_PATH}" >"${CHECKSUM_PATH}"
printf 'SwiftPM artifact: %s\n' "${ZIP_PATH}"
printf 'SwiftPM checksum: %s\n' "$(cat "${CHECKSUM_PATH}")"
