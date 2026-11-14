#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

model_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
proof_output=$(mktemp)
trap 'rm -f -- "$proof_output"' EXIT

if ! tamarin-prover --prove --quit-on-warning --derivcheck-timeout=90 "$model_dir/hpke.spthy" >"$proof_output" 2>&1; then
  cat -- "$proof_output" >&2
  exit 1
fi

# The prover can exit successfully with falsified or incomplete lemmas.
if ! awk '
  /^summary of summaries:$/ { summary = 1 }
  !summary { next }
  { print }
  $2 ~ /^\((all-traces|exists-trace)\):$/ {
    if ($3 == "verified") {
      verified[$1] = $2
    } else {
      failed = 1
    }
  }
  END {
    exit (failed ||
          verified["base_roundtrip_exists"] != "(exists-trace):" ||
          verified["psk_roundtrip_exists"] != "(exists-trace):" ||
          verified["successful_open_binds_context"] != "(all-traces):" ||
          verified["successful_open_binds_psk_identifier"] != "(all-traces):" ||
          verified["base_export_agreement_exists"] != "(exists-trace):" ||
          verified["psk_export_agreement_exists"] != "(exists-trace):" ||
          verified["alternate_psk_identifier_can_be_selected"] != "(exists-trace):" ||
          verified["matching_exports_bind_context"] != "(all-traces):" ||
          verified["plaintext_secrecy"] != "(all-traces):")
  }
' "$proof_output"; then
  printf '%s\n' 'HPKE verification requires a complete, verified proof of every lemma.' >&2
  exit 1
fi
