#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

# These tests consume the committed upstream corpora. Re-vendoring is a
# separate operation; source-ref inputs must not gate the audit itself.
adapters=(
  'wycheproof_chacha20_poly1305:wycheproof_chacha20_poly1305_vectors_execute_against_public_api'
  'wycheproof_ecdsa_secp256k1:wycheproof_ecdsa_secp256k1_sha256_vectors_execute_against_public_api'
  'wycheproof_xdh_x25519:wycheproof_x25519_vectors_execute_against_public_api'
  'wycheproof_xdh_x448:wycheproof_x448_vectors_execute_against_public_api'
  'wycheproof_ecdh_pcurves:wycheproof_ecdh_p256_vectors_execute_against_public_api'
  'wycheproof_ecdh_pcurves:wycheproof_ecdh_p384_vectors_execute_against_public_api'
  'wycheproof_ecdh_pcurves:wycheproof_ecdh_p521_vectors_execute_against_public_api'
  'bip340_schnorr:bip340_schnorr_verification_vectors_execute_against_public_api'
  'rfc8032_ed25519_siggen:rfc8032_ed25519_siggen_vectors_match_public_signer'
  'xwing768_kat:xwing768_draft_vectors_match_public_api'
  'rfc9180_hpke:rfc9180_hpke_base_vectors_execute_against_public_api'
  'pbkdf2_rfc6070:pbkdf2_rfc6070_derived_vectors_match_public_api'
)

for adapter in "${adapters[@]}"; do
  test_file="${adapter%%:*}"
  test_name="${adapter#*:}"
  bash scripts/run_exact_cargo_test.sh --ignored "$test_name" \
    --locked -p external-vector-audit --no-default-features --features native \
    --test "$test_file"
done
