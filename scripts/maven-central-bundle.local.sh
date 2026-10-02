#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail
IFS=$'\n\t'

# Load MAVEN_SIGNING_PASSWORD from a secret manager or a non-echoing prompt
# before running; do not put the passphrase in shell history.
# Usage:
#   MAVEN_SIGNING_KEY_ID=<long-gpg-key-id-or-fingerprint> \
#   ANDROID_NDK_HOME=/path/to/android-ndk \
#   ./scripts/maven-central-bundle.local.sh
#
# Output:
#   build/maven-central-upload/out/reallyme-maven-central-<version>.zip
#
# Upload the printed zip in Central Portal as a deployment bundle. The bundle is
# assembled in Maven repository layout and includes the JVM jar and Android AAR.
# The JVM libraries come from the latest successful versioned Kotlin/Android
# package preflight for the current main commit. This script never dispatches
# a workflow or substitutes locally built release libraries.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${MAVEN_CENTRAL_WORK_DIR:-${ROOT_DIR}/build/maven-central-upload}"
BUNDLE_ROOT="${WORK_DIR}/bundle-root"
OUTPUT_DIR="${WORK_DIR}/out"
GRADLE="${ROOT_DIR}/packages/kotlin/gradlew"
ANDROID_GRADLE="${ROOT_DIR}/packages/kotlin-android/gradlew"
KOTLIN_NATIVE_RESOURCES_DIR="${WORK_DIR}/kotlin-native-resources"
ANDROID_JNI_LIBS_DIR_WAS_SET="${ANDROID_JNI_LIBS_DIR+x}"
ANDROID_JNI_LIBS_DIR="${ANDROID_JNI_LIBS_DIR:-${WORK_DIR}/android-jniLibs}"
ANDROID_NATIVE_ASSETS_DIR="${WORK_DIR}/android-native-assets"
ANDROID_NDK_VERSION="${ANDROID_NDK_VERSION:-29.0.14206865}"
NATIVE_RESOURCE_ARTIFACT_PATTERN="kotlin-native-*"
NATIVE_RESOURCE_DOWNLOAD_DIR="${WORK_DIR}/kotlin-native-artifacts"
NATIVE_RESOURCE_RUN_ID="${MAVEN_NATIVE_RESOURCE_RUN_ID:-}"

fail() {
  printf 'maven central bundle failed: %s\n' "$1" >&2
  exit 1
}

info() {
  printf '%s\n' "$1" >&2
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required tool not found: $1"
  fi
}

read_gradle_version() {
  local file="$1"
  sed -n 's/^version = "\([^"]*\)".*/\1/p' "$file" | head -n 1
}

require_file() {
  if [ ! -f "$1" ]; then
    fail "missing required file: $1"
  fi
}

require_dir() {
  if [ ! -d "$1" ]; then
    fail "missing required directory: $1"
  fi
}

validate_work_dir() {
  case "$WORK_DIR" in
    /*) ;;
    *) fail "MAVEN_CENTRAL_WORK_DIR must be an absolute path" ;;
  esac
  case "/${WORK_DIR}/" in
    *'/../'*|*'/./'*) fail "MAVEN_CENTRAL_WORK_DIR must not contain dot path segments" ;;
  esac
  case "$WORK_DIR" in
    /|"$ROOT_DIR"|"$ROOT_DIR"/) fail "MAVEN_CENTRAL_WORK_DIR must name a dedicated build directory" ;;
  esac
  if [ -L "$WORK_DIR" ]; then
    fail "MAVEN_CENTRAL_WORK_DIR must not be a symbolic link"
  fi
}

require_zip_entry() {
  local archive="$1"
  local entry="$2"
  if ! jar tf "$archive" | grep -Fx -- "$entry" >/dev/null; then
    fail "$archive is missing archive entry: $entry"
  fi
}

reject_zip_entry_prefix() {
  local archive="$1"
  local prefix="$2"
  if jar tf "$archive" | grep -F -- "$prefix" >/dev/null; then
    fail "$archive contains forbidden archive entries with prefix: $prefix"
  fi
}

kotlin_native_resource_files() {
  printf '%s\n' \
    "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/crypto/native/linux-x86_64/libcrypto_ffi.so" \
    "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/crypto/native/linux-aarch64/libcrypto_ffi.so" \
    "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/crypto/native/macos-x86_64/libcrypto_ffi.dylib" \
    "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/crypto/native/macos-aarch64/libcrypto_ffi.dylib" \
    "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/crypto/native/windows-x86_64/crypto_ffi.dll"
}

kotlin_native_resource_root() {
  printf '%s\n' "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/crypto/native"
}

kotlin_native_resources_are_complete() {
  local native_file
  while IFS= read -r native_file; do
    if [ ! -f "$native_file" ]; then
      return 1
    fi
  done < <(kotlin_native_resource_files)
  return 0
}

download_kotlin_native_resources_from_run() {
  local run_id="$1"
  local artifact_name

  rm -rf "$NATIVE_RESOURCE_DOWNLOAD_DIR" "$KOTLIN_NATIVE_RESOURCES_DIR"
  mkdir -p "$NATIVE_RESOURCE_DOWNLOAD_DIR" "$KOTLIN_NATIVE_RESOURCES_DIR"
  info "Downloading JVM native resource artifacts from GitHub Actions run ${run_id}"
  gh run download "$run_id" --repo reallyme/crypto \
    --pattern "$NATIVE_RESOURCE_ARTIFACT_PATTERN" \
    --dir "$NATIVE_RESOURCE_DOWNLOAD_DIR"

  for artifact_name in \
    kotlin-native-linux-x86_64 \
    kotlin-native-linux-aarch64 \
    kotlin-native-macos-x86_64 \
    kotlin-native-macos-aarch64 \
    kotlin-native-windows-x86_64; do
    require_dir "${NATIVE_RESOURCE_DOWNLOAD_DIR}/${artifact_name}"
    cp -R "${NATIVE_RESOURCE_DOWNLOAD_DIR}/${artifact_name}/." "$KOTLIN_NATIVE_RESOURCES_DIR/"
  done
}

verify_release_preflight() {
  local output_file
  local run_id
  local output_line

  require_tool gh
  require_tool git
  if [ -n "$(git -C "$ROOT_DIR" status --porcelain)" ]; then
    fail "release checkout has uncommitted changes"
  fi

  RELEASE_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD)"
  if [[ ! "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    fail "release checkout does not have a valid commit SHA"
  fi
  output_file="$(mktemp "${WORK_DIR}/release-attestation.XXXXXX")"
  if ! GH_TOKEN="${GH_TOKEN:-$(gh auth token)}" \
    GITHUB_REPOSITORY="reallyme/crypto" \
    RELEASE_SHA="$RELEASE_SHA" \
    RELEASE_VERSION="$VERSION" \
    RELEASE_ATTESTATION_PREFLIGHT_WORKFLOW="kotlin-android-package-preflight.yml" \
    RELEASE_ATTESTATION_WRITE_GITHUB_OUTPUT=1 \
    GITHUB_OUTPUT="$output_file" \
      node "${ROOT_DIR}/scripts/verify_release_attestation.mjs"; then
    rm -f "$output_file"
    fail "current main commit lacks successful release and package preflight evidence"
  fi
  output_line="$(cat "$output_file")"
  rm -f "$output_file"
  if [[ ! "$output_line" =~ ^preflight_run_id=([1-9][0-9]*)$ ]]; then
    fail "release attestation did not return a valid preflight run id"
  fi
  run_id="${BASH_REMATCH[1]}"
  if [ -n "$NATIVE_RESOURCE_RUN_ID" ] && [ "$NATIVE_RESOURCE_RUN_ID" != "$run_id" ]; then
    fail "selected native-resource run is not the latest attested package preflight"
  fi
  NATIVE_RESOURCE_RUN_ID="$run_id"
}

ensure_kotlin_native_resources() {
  download_kotlin_native_resources_from_run "$NATIVE_RESOURCE_RUN_ID"
  if ! kotlin_native_resources_are_complete; then
    fail "attested preflight ${NATIVE_RESOURCE_RUN_ID} has incomplete JVM native resources"
  fi
}

prepare_android_ndk_home() {
  if [ -n "${ANDROID_NDK_HOME:-}" ]; then
    return
  fi
  if [ -n "${ANDROID_HOME:-}" ] && [ -d "${ANDROID_HOME}/ndk/${ANDROID_NDK_VERSION}" ]; then
    export ANDROID_NDK_HOME="${ANDROID_HOME}/ndk/${ANDROID_NDK_VERSION}"
    return
  fi
  fail "ANDROID_NDK_HOME is not set and ${ANDROID_HOME:-\$ANDROID_HOME}/ndk/${ANDROID_NDK_VERSION} was not found"
}

write_checksums() {
  local root="$1"
  node - "$root" <<'NODE'
const { createHash } = require("node:crypto");
const { readdirSync, readFileSync, statSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");

const root = process.argv[2];
const checksumExtensions = new Set([".md5", ".sha1", ".sha256", ".sha512"]);
const algorithms = [
  ["md5", ".md5"],
  ["sha1", ".sha1"],
  ["sha256", ".sha256"],
  ["sha512", ".sha512"],
];

function walk(directory) {
  const entries = [];
  for (const dirent of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, dirent.name);
    if (dirent.isDirectory()) {
      entries.push(...walk(path));
    } else if (dirent.isFile()) {
      entries.push(path);
    }
  }
  return entries;
}

if (!statSync(root).isDirectory()) {
  throw new Error(`${root} is not a directory`);
}

for (const path of walk(root)) {
  if (checksumExtensions.has(path.slice(path.lastIndexOf(".")))) {
    continue;
  }
  const bytes = readFileSync(path);
  for (const [algorithm, extension] of algorithms) {
    writeFileSync(`${path}${extension}`, `${createHash(algorithm).update(bytes).digest("hex")}\n`);
  }
}
NODE
}

validate_bundle_files() {
  local version="$1"
  local jvm_dir="${BUNDLE_ROOT}/me/really/crypto/${version}"
  local android_dir="${BUNDLE_ROOT}/me/really/crypto-android/${version}"

  require_dir "$jvm_dir"
  require_dir "$android_dir"

  for file in \
    "${jvm_dir}/crypto-${version}.jar" \
    "${jvm_dir}/crypto-${version}-sources.jar" \
    "${jvm_dir}/crypto-${version}-javadoc.jar" \
    "${jvm_dir}/crypto-${version}.pom" \
    "${jvm_dir}/crypto-${version}.module" \
    "${android_dir}/crypto-android-${version}.aar" \
    "${android_dir}/crypto-android-${version}-sources.jar" \
    "${android_dir}/crypto-android-${version}.pom" \
    "${android_dir}/crypto-android-${version}.module"; do
    require_file "$file"
    require_file "${file}.asc"
    require_file "${file}.md5"
    require_file "${file}.sha1"
    require_file "${file}.sha256"
    require_file "${file}.sha512"
    require_file "${file}.asc.md5"
    require_file "${file}.asc.sha1"
    require_file "${file}.asc.sha256"
    require_file "${file}.asc.sha512"
  done

  local jvm_jar="${jvm_dir}/crypto-${version}.jar"
  require_zip_entry "$jvm_jar" "me/really/crypto/native/linux-x86_64/libcrypto_ffi.so"
  require_zip_entry "$jvm_jar" "me/really/crypto/native/linux-aarch64/libcrypto_ffi.so"
  require_zip_entry "$jvm_jar" "me/really/crypto/native/macos-x86_64/libcrypto_ffi.dylib"
  require_zip_entry "$jvm_jar" "me/really/crypto/native/macos-aarch64/libcrypto_ffi.dylib"
  require_zip_entry "$jvm_jar" "me/really/crypto/native/windows-x86_64/crypto_ffi.dll"
  require_zip_entry "$jvm_jar" "me/really/crypto/native/native-manifest.json"
  reject_zip_entry_prefix "${jvm_dir}/crypto-${version}-sources.jar" "me/really/crypto/native/"
  reject_zip_entry_prefix "${android_dir}/crypto-android-${version}-sources.jar" "jni/"
  reject_zip_entry_prefix "${android_dir}/crypto-android-${version}-sources.jar" "assets/reallyme-crypto/"

  local android_aar="${android_dir}/crypto-android-${version}.aar"
  require_zip_entry "$android_aar" "jni/arm64-v8a/libcrypto_ffi.so"
  require_zip_entry "$android_aar" "jni/armeabi-v7a/libcrypto_ffi.so"
  require_zip_entry "$android_aar" "jni/x86_64/libcrypto_ffi.so"
  require_zip_entry "$android_aar" "jni/x86/libcrypto_ffi.so"
  require_zip_entry "$android_aar" "assets/reallyme-crypto/native-manifest.json"
}

sign_bundle_files() {
  local root="$1"
  local file

  find "$root" -type f -name '*.asc' -delete
  while IFS= read -r -d '' file; do
    case "$file" in
      *.md5|*.sha1|*.sha256|*.sha512)
        continue
        ;;
    esac
    gpg \
      --batch \
      --yes \
      --pinentry-mode loopback \
      --passphrase-fd 0 \
      --local-user "$MAVEN_SIGNING_KEY_ID" \
      --armor \
      --detach-sign \
      --output "${file}.asc" \
      "$file" <<<"$MAVEN_SIGNING_PASSWORD"
  done < <(find "$root" -type f -print0)
}

verify_bundle_signatures() {
  local root="$1"
  local signature
  local artifact

  while IFS= read -r -d '' signature; do
    artifact="${signature%.asc}"
    require_file "$artifact"
    if ! gpg --batch --verify "$signature" "$artifact" >/dev/null 2>&1; then
      fail "bundle contains an invalid detached signature"
    fi
  done < <(find "$root" -type f -name '*.asc' -print0)
}

remove_local_repository_metadata() {
  local root="$1"
  find "$root" -type f -name 'maven-metadata.xml*' -delete
}

require_tool cargo
require_tool find
require_tool grep
require_tool gpg
require_tool jar
require_tool node
require_tool rustup
require_tool sed
require_tool sleep
require_tool zip
validate_work_dir

if [ -z "${MAVEN_SIGNING_PASSWORD:-}" ]; then
  fail "MAVEN_SIGNING_PASSWORD must contain the GPG private key passphrase"
fi
if [ -z "${MAVEN_SIGNING_KEY_ID:-}" ]; then
  fail "MAVEN_SIGNING_KEY_ID must contain the GPG secret key id or fingerprint"
fi
GPG_SIGN_ARGS=(
  --batch
  --yes
  --pinentry-mode
  loopback
  --passphrase-fd
  0
  --armor
  --detach-sign
  --output
  /dev/null
  --local-user
  "$MAVEN_SIGNING_KEY_ID"
)
if ! printf '%s' "$MAVEN_SIGNING_PASSWORD" | gpg "${GPG_SIGN_ARGS[@]}" >/dev/null 2>&1; then
  fail "GPG could not sign with the configured key id and passphrase; check MAVEN_SIGNING_KEY_ID and MAVEN_SIGNING_PASSWORD"
fi

VERSION="${MAVEN_RELEASE_VERSION:-$(read_gradle_version "${ROOT_DIR}/packages/kotlin/build.gradle.kts")}"
ANDROID_VERSION="$(read_gradle_version "${ROOT_DIR}/packages/kotlin-android/build.gradle.kts")"
if [ -z "$VERSION" ]; then
  fail "unable to read JVM package version"
fi
if [ "$VERSION" != "$ANDROID_VERSION" ]; then
  fail "JVM package version $VERSION does not match Android package version $ANDROID_VERSION"
fi
if [[ "$VERSION" == *SNAPSHOT* ]]; then
  fail "Central Portal release bundles must not use SNAPSHOT versions"
fi

require_file "$GRADLE"
require_file "$ANDROID_GRADLE"
mkdir -p "$WORK_DIR"
info "Using version ${VERSION}"
verify_release_preflight
info "Using JVM native resources from ${KOTLIN_NATIVE_RESOURCES_DIR}"
ensure_kotlin_native_resources
info "Writing JVM native checksum manifest"
node "${ROOT_DIR}/scripts/write_native_manifest.mjs" \
  "$(kotlin_native_resource_root)" \
  "$(kotlin_native_resource_root)/native-manifest.json"

while IFS= read -r native_file; do
  require_file "$native_file"
done < <(kotlin_native_resource_files)
require_file "$(kotlin_native_resource_root)/native-manifest.json"

if [ -z "$ANDROID_JNI_LIBS_DIR_WAS_SET" ]; then
  prepare_android_ndk_home
  info "Building Android JNI libraries into ${ANDROID_JNI_LIBS_DIR}"
  rm -rf "$ANDROID_JNI_LIBS_DIR"
  "${ROOT_DIR}/scripts/build_android_native_resources.sh" "$ANDROID_JNI_LIBS_DIR"
else
  require_dir "$ANDROID_JNI_LIBS_DIR"
  info "Using Android JNI libraries from ${ANDROID_JNI_LIBS_DIR}"
fi

info "Writing Android native checksum manifest"
rm -rf "$ANDROID_NATIVE_ASSETS_DIR"
node "${ROOT_DIR}/scripts/write_native_manifest.mjs" \
  "$ANDROID_JNI_LIBS_DIR" \
  "${ANDROID_NATIVE_ASSETS_DIR}/reallyme-crypto/native-manifest.json"

rm -rf \
  "${ROOT_DIR}/packages/kotlin/build/repos/releases" \
  "${ROOT_DIR}/packages/kotlin-android/build/repos/releases" \
  "$BUNDLE_ROOT"
mkdir -p "$BUNDLE_ROOT" "$OUTPUT_DIR"

info "Publishing JVM artifacts to the local release repository"
(
  unset MAVEN_SIGNING_KEY MAVEN_SIGNING_PASSWORD
  "$GRADLE" -p "${ROOT_DIR}/packages/kotlin" \
    test \
    publishMavenPublicationToLocalReleaseRepository \
    -Preallyme.crypto.nativeResourcesDir="$KOTLIN_NATIVE_RESOURCES_DIR" \
    -Preallyme.crypto.requireFullNativeResources=true
)

info "Publishing Android artifacts to the local release repository"
(
  unset MAVEN_SIGNING_KEY MAVEN_SIGNING_PASSWORD
  "$ANDROID_GRADLE" -p "${ROOT_DIR}/packages/kotlin-android" \
    check \
    publishAndroidReleasePublicationToLocalReleaseRepository \
    -Preallyme.crypto.androidJniLibsDir="$ANDROID_JNI_LIBS_DIR" \
    -Preallyme.crypto.androidNativeAssetsDir="$ANDROID_NATIVE_ASSETS_DIR" \
    -Preallyme.crypto.requireAndroidJniLibs=true
)

info "Assembling Maven repository-layout bundle"
cp -R "${ROOT_DIR}/packages/kotlin/build/repos/releases/." "$BUNDLE_ROOT/"
cp -R "${ROOT_DIR}/packages/kotlin-android/build/repos/releases/." "$BUNDLE_ROOT/"

info "Removing local Maven repository metadata"
remove_local_repository_metadata "$BUNDLE_ROOT"

info "Signing Maven bundle files with local GPG"
sign_bundle_files "$BUNDLE_ROOT"

info "Verifying Maven bundle signatures"
verify_bundle_signatures "$BUNDLE_ROOT"

info "Writing checksums for artifacts and signatures"
write_checksums "$BUNDLE_ROOT"

info "Validating bundle contents"
validate_bundle_files "$VERSION"

BUNDLE_ZIP="${OUTPUT_DIR}/reallyme-maven-central-${VERSION}.zip"
rm -f "$BUNDLE_ZIP"
info "Creating ${BUNDLE_ZIP}"
(
  cd "$BUNDLE_ROOT"
  COPYFILE_DISABLE=1 zip -X -q -r "$BUNDLE_ZIP" .
)

require_file "$BUNDLE_ZIP"
info "Maven Central upload bundle ready:"
printf '%s\n' "$BUNDLE_ZIP"
