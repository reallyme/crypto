#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_PACKAGE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${ANDROID_PACKAGE_DIR}/../.." && pwd)"

ANDROID_SDK_ROOT_VALUE="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
ANDROID_NDK_VERSION="${REALLYME_ANDROID_NDK_VERSION:-29.0.14206865}"
if [[ -z "${ANDROID_SDK_ROOT_VALUE}" ]]; then
  echo "ANDROID_HOME or ANDROID_SDK_ROOT must point at an Android SDK" >&2
  exit 1
fi

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  ANDROID_NDK_HOME="${ANDROID_SDK_ROOT_VALUE}/ndk/${ANDROID_NDK_VERSION}"
  export ANDROID_NDK_HOME
fi
if [[ -z "${ANDROID_NDK_HOME}" || ! -d "${ANDROID_NDK_HOME}" ]]; then
  echo "Android NDK ${ANDROID_NDK_VERSION} not found under ${ANDROID_SDK_ROOT_VALUE}/ndk" >&2
  exit 1
fi

JNI_LIBS_DIR="${1:-${ANDROID_PACKAGE_DIR}/src/main/jniLibs}"
export ANDROID_API="${REALLYME_ANDROID_API_LEVEL:-26}"

exec "${REPO_ROOT}/scripts/build_android_native_resources.sh" "${JNI_LIBS_DIR}"
