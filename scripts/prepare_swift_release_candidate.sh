#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [ "$#" -ne 1 ]; then
  printf 'usage: scripts/prepare_swift_release_candidate.sh <version>\n' >&2
  exit 2
fi

RELEASE_VERSION_INPUT="$1"
if [[ ! "${RELEASE_VERSION_INPUT}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf 'release version must be exact semantic versioning without a leading v\n' >&2
  exit 2
fi

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE_PATH="${REPOSITORY_ROOT}/build/swift/ReallyMeCryptoFFI.xcframework.zip"
CHECKSUM_PATH="${REPOSITORY_ROOT}/build/swift/ReallyMeCryptoFFI.xcframework.checksum"

cd "${REPOSITORY_ROOT}"

# Build from the complete release working tree before the release commit is
# created. Package.swift does not participate in the Rust FFI build, so writing
# its checksum afterward cannot change the archive bytes being committed to.
scripts/build_swift_xcframework.sh

IFS= read -r SWIFTPM_CHECKSUM <"${CHECKSUM_PATH}"
if [[ ! "${SWIFTPM_CHECKSUM}" =~ ^[0-9a-f]{64}$ ]]; then
  printf 'generated SwiftPM checksum is malformed\n' >&2
  exit 1
fi

node scripts/prepare_swift_binary_manifest.mjs \
  "${RELEASE_VERSION_INPUT}" \
  "${SWIFTPM_CHECKSUM}"
node scripts/verify_swift_release_artifact.mjs \
  "${ARCHIVE_PATH}" \
  "${CHECKSUM_PATH}" \
  Package.swift \
  "${RELEASE_VERSION_INPUT}"

printf 'Prepared Package.swift for %s with SwiftPM checksum %s\n' \
  "${RELEASE_VERSION_INPUT}" \
  "${SWIFTPM_CHECKSUM}"
