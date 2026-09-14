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
swift test -Xswiftc -warnings-as-errors
swift test --package-path crates/conformance/platform/swift -Xswiftc -warnings-as-errors
