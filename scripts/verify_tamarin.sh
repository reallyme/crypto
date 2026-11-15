#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

proof_log=$(mktemp)
trap 'rm -f -- "$proof_log"' EXIT

if ! tamarin-prover --prove --quit-on-warning --derivcheck-timeout=90 formal/tamarin/hpke_base.spthy >"$proof_log" 2>&1; then
  cat -- "$proof_log" >&2
  exit 1
fi
# A zero exit status alone does not prove that both lemmas were verified.
awk '
  /^summary of summaries:$/ { summary = 1 }
  !summary { next }
  { print }
  $1 == "sanity_roundtrip_exists" && $2 == "(exists-trace):" && $3 == "verified" { executable = 1 }
  $1 == "plaintext_secrecy" && $2 == "(all-traces):" && $3 == "verified" { secrecy = 1 }
  $2 ~ /^\((all-traces|exists-trace)\):$/ && $3 != "verified" { failed = 1 }
  END { exit !(executable && secrecy && !failed) }
' "$proof_log"
