#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

swift format lint --configuration .swift-format --recursive --strict \
  packages/swift/Sources \
  packages/swift/Tests \
  crates/conformance/platform/swift/Sources \
  crates/conformance/platform/swift/Tests

# Both Swift packages target Apple platforms and use Apple-only frameworks such
# as CryptoKit, Security, and LocalAuthentication. Ubuntu policy jobs still
# enforce formatting, while the dedicated macOS job performs strict compilation
# and testing through this same script.
if [[ "$(uname -s)" != "Darwin" ]]; then
  exit 0
fi

swift test -Xswiftc -warnings-as-errors
swift test --package-path crates/conformance/platform/swift -Xswiftc -warnings-as-errors
