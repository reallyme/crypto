#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ignored=0
if [[ "${1:-}" == "--ignored" ]]; then
  ignored=1
  shift
fi
if [[ "$#" -lt 2 || -z "$1" ]]; then
  echo "usage: run_exact_cargo_test.sh [--ignored] TEST_NAME CARGO_TEST_OPTIONS..." >&2
  exit 2
fi

test_name="$1"
shift
test_options=(--exact)
if [[ "$ignored" -eq 1 ]]; then
  test_options+=(--ignored)
fi

if ! output="$(cargo test "$@" "$test_name" -- "${test_options[@]}" 2>&1)"; then
  printf '%s\n' "$output"
  exit 1
fi
printf '%s\n' "$output"
if [[ "$output" != *"test result: ok. 1 passed; 0 failed;"* ]]; then
  echo "the exact Cargo test did not execute once: ${test_name}" >&2
  exit 1
fi
