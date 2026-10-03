#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Build the repository whose artifacts we stage, even from another working
# directory or with an ambient CARGO_TARGET_DIR override.
# Cargo gives encoded flags precedence over RUSTFLAGS. Release packaging owns
# the complete codegen policy, so inherited encoded flags must not participate.
unset CARGO_ENCODED_RUSTFLAGS
BUILD_DIR="${ROOT_DIR}/build/swift"
HEADERS_DIR="${BUILD_DIR}/headers"
FRAMEWORK_DIR="${BUILD_DIR}/ReallyMeCryptoFFI.xcframework"
ZIP_PATH="${BUILD_DIR}/ReallyMeCryptoFFI.xcframework.zip"
CHECKSUM_PATH="${BUILD_DIR}/ReallyMeCryptoFFI.xcframework.checksum"
DYLIB_INSTALL_NAME="@rpath/ReallyMeCryptoFFI.framework/ReallyMeCryptoFFI"
PACKAGE_VERSION="$(sed -n 's/^version = "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"$/\1/p' "${ROOT_DIR}/crates/ffi/Cargo.toml")"

if [[ ! "${PACKAGE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'could not read the crypto-ffi package version\n' >&2
  exit 1
fi

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required tool not found: %s\n' "$1" >&2
    exit 1
  fi
}

build_target() {
  local target="$1"
  rustup target add "${target}"
  # Do not let ambient codegen flags override the audited panic strategy.
  RUSTFLAGS="" cargo build --locked -p crypto-ffi \
    --manifest-path "${ROOT_DIR}/Cargo.toml" \
    --target-dir "${ROOT_DIR}/target" \
    --profile release-ffi \
    --target "${target}"
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

make_framework() {
  local platform="$1"
  local library="$2"
  local framework="${BUILD_DIR}/frameworks/${platform}/ReallyMeCryptoFFI.framework"
  mkdir -p "${framework}/Headers" "${framework}/Modules"
  cp "${library}" "${framework}/ReallyMeCryptoFFI"
  install_name_tool -id "${DYLIB_INSTALL_NAME}" "${framework}/ReallyMeCryptoFFI"
  cp "${HEADERS_DIR}/reallyme_crypto_ffi.h" "${framework}/Headers/"
  cat >"${framework}/Modules/module.modulemap" <<'MODULEMAP'
framework module ReallyMeCryptoFFI {
  header "reallyme_crypto_ffi.h"
  export *
}
MODULEMAP
  cat >"${framework}/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>ReallyMeCryptoFFI</string>
  <key>CFBundleIdentifier</key><string>me.really.crypto.ffi</string>
  <key>CFBundleName</key><string>ReallyMeCryptoFFI</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
  <key>CFBundleShortVersionString</key><string>${PACKAGE_VERSION}</string>
  <key>CFBundleVersion</key><string>${PACKAGE_VERSION}</string>
</dict>
</plist>
PLIST
}

normalize_xcframework_info_plist() {
  # xcodebuild does not guarantee AvailableLibraries ordering. SwiftPM hashes
  # the raw archive, so canonicalize the plist before normalizing zip metadata.
  cat >"${FRAMEWORK_DIR}/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AvailableLibraries</key>
	<array>
		<dict>
			<key>BinaryPath</key>
			<string>ReallyMeCryptoFFI.framework/ReallyMeCryptoFFI</string>
			<key>LibraryIdentifier</key>
			<string>macos-arm64_x86_64</string>
			<key>LibraryPath</key>
			<string>ReallyMeCryptoFFI.framework</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
				<string>x86_64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>macos</string>
		</dict>
		<dict>
			<key>BinaryPath</key>
			<string>ReallyMeCryptoFFI.framework/ReallyMeCryptoFFI</string>
			<key>LibraryIdentifier</key>
			<string>ios-arm64</string>
			<key>LibraryPath</key>
			<string>ReallyMeCryptoFFI.framework</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
		</dict>
		<dict>
			<key>BinaryPath</key>
			<string>ReallyMeCryptoFFI.framework/ReallyMeCryptoFFI</string>
			<key>LibraryIdentifier</key>
			<string>ios-arm64_x86_64-simulator</string>
			<key>LibraryPath</key>
			<string>ReallyMeCryptoFFI.framework</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
				<string>x86_64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
			<key>SupportedPlatformVariant</key>
			<string>simulator</string>
		</dict>
	</array>
	<key>CFBundlePackageType</key>
	<string>XFWK</string>
	<key>XCFrameworkFormatVersion</key>
	<string>1.0</string>
</dict>
</plist>
PLIST
}

verify_xcframework_layout() {
  local slice framework binary install_name
  for slice in macos-arm64_x86_64 ios-arm64 ios-arm64_x86_64-simulator; do
    framework="${FRAMEWORK_DIR}/${slice}/ReallyMeCryptoFFI.framework"
    binary="${framework}/ReallyMeCryptoFFI"
    if [ ! -f "${binary}" ] || [ ! -f "${framework}/Headers/reallyme_crypto_ffi.h" ] || \
      [ ! -f "${framework}/Modules/module.modulemap" ]; then
      printf 'incomplete SwiftPM dynamic framework slice: %s\n' "${slice}" >&2
      exit 1
    fi
    install_name="$(otool -D "${binary}" | tail -n 1)"
    if [ "${install_name}" != "${DYLIB_INSTALL_NAME}" ]; then
      printf 'unexpected dynamic framework install name: %s\n' "${slice}" >&2
      exit 1
    fi
  done
}

require_tool cargo
require_tool rustup
require_tool xcodebuild
require_tool lipo
require_tool install_name_tool
require_tool otool
require_tool find
require_tool sort
require_tool swift
require_tool touch
require_tool zip

rm -rf "${BUILD_DIR}"
mkdir -p "${HEADERS_DIR}" "${BUILD_DIR}/libs"
cp "${ROOT_DIR}/crates/ffi/abi/reallyme_crypto_ffi.h" \
  "${HEADERS_DIR}/reallyme_crypto_ffi.h"

build_target aarch64-apple-darwin
build_target x86_64-apple-darwin
build_target aarch64-apple-ios
build_target aarch64-apple-ios-sim
build_target x86_64-apple-ios

copy_or_lipo \
  "${BUILD_DIR}/libs/libcrypto_ffi_macos.dylib" \
  "${ROOT_DIR}/target/aarch64-apple-darwin/release-ffi/libcrypto_ffi.dylib" \
  "${ROOT_DIR}/target/x86_64-apple-darwin/release-ffi/libcrypto_ffi.dylib"

copy_or_lipo \
  "${BUILD_DIR}/libs/libcrypto_ffi_ios.dylib" \
  "${ROOT_DIR}/target/aarch64-apple-ios/release-ffi/libcrypto_ffi.dylib"

copy_or_lipo \
  "${BUILD_DIR}/libs/libcrypto_ffi_ios_simulator.dylib" \
  "${ROOT_DIR}/target/aarch64-apple-ios-sim/release-ffi/libcrypto_ffi.dylib" \
  "${ROOT_DIR}/target/x86_64-apple-ios/release-ffi/libcrypto_ffi.dylib"

# Codec ships its own Rust static library. Keeping Crypto in a separate
# dynamically linked framework prevents the two Rust runtimes from defining
# the same process-level exception personality symbol at the final link.
make_framework macos "${BUILD_DIR}/libs/libcrypto_ffi_macos.dylib"
make_framework ios "${BUILD_DIR}/libs/libcrypto_ffi_ios.dylib"
make_framework ios-simulator "${BUILD_DIR}/libs/libcrypto_ffi_ios_simulator.dylib"

xcodebuild -create-xcframework \
  -framework "${BUILD_DIR}/frameworks/macos/ReallyMeCryptoFFI.framework" \
  -framework "${BUILD_DIR}/frameworks/ios/ReallyMeCryptoFFI.framework" \
  -framework "${BUILD_DIR}/frameworks/ios-simulator/ReallyMeCryptoFFI.framework" \
  -output "${FRAMEWORK_DIR}"

normalize_xcframework_info_plist
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
