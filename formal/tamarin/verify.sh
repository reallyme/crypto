#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

model_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
proof_output=$(mktemp)
trap 'rm -f -- "$proof_output"' EXIT

verify_model() {
  local model=$1
  shift
  printf 'Verifying %s\n' "$model"
  if ! tamarin-prover --prove --quit-on-warning --derivcheck-timeout=90 "$model_dir/$model" >"$proof_output" 2>&1; then
    cat -- "$proof_output" >&2
    return 1
  fi

  # The prover can exit successfully with falsified or incomplete lemmas.
  if ! awk -v required="$*" '
    BEGIN {
      count = split(required, lemmas, " ")
      for (i = 1; i <= count; i++) {
        split(lemmas[i], entry, ":")
        expected[entry[1]] = "(" entry[2] "):"
      }
    }
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
      for (lemma in expected) {
        if (verified[lemma] != expected[lemma]) {
          failed = 1
        }
      }
      exit failed
    }
  ' "$proof_output"; then
    printf '%s requires a complete, verified proof of every lemma.\n' "$model" >&2
    return 1
  fi
}

verify_model hpke.spthy \
  base_roundtrip_exists:exists-trace \
  psk_roundtrip_exists:exists-trace \
  successful_open_binds_context:all-traces \
  successful_open_binds_psk_identifier:all-traces \
  base_export_agreement_exists:exists-trace \
  psk_export_agreement_exists:exists-trace \
  alternate_psk_identifier_can_be_selected:exists-trace \
  matching_exports_bind_context:all-traces \
  plaintext_secrecy:all-traces

verify_model hpke_pq.spthy \
  mlkem_roundtrip_exists:exists-trace \
  xwing_roundtrip_exists:exists-trace \
  mlkem_fallback_exports_and_rejects_exists:exists-trace \
  xwing_fallback_exports_and_rejects_exists:exists-trace \
  malformed_rejects_exists:exists-trace \
  malformed_cannot_export_or_open:all-traces \
  implicit_rejection_cannot_authenticate:all-traces \
  plaintext_release_requires_authentication:all-traces \
  xwing_record_authentication_binds_encapsulation:all-traces \
  mlkem_psk_roundtrip_exists:exists-trace \
  xwing_psk_roundtrip_exists:exists-trace \
  psk_open_binds_identifier_and_info:all-traces \
  matching_psk_fallback_keys_bind_identifier_and_info:all-traces \
  alternate_psk_identifier_after_fallback_exists:exists-trace \
  alternate_info_after_psk_fallback_exists:exists-trace
