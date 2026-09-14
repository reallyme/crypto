#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

packages/kotlin/gradlew \
  --dependency-verification strict \
  -p packages/kotlin \
  check
packages/kotlin-android/gradlew \
  --dependency-verification strict \
  -p packages/kotlin-android \
  check
crates/conformance/platform/kotlin/gradlew \
  --dependency-verification strict \
  -p crates/conformance/platform/kotlin \
  check
