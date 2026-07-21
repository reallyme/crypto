// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

pub(crate) fn run() -> Result<(), VectorGenError> {
    let dir = vectors_dir()?;
    ensure_dir(&dir)?;

    let keys = generate_keys()?;
    write_key_vectors(&dir, &keys)?;
    write_aes128_gcm_vector(&dir)?;
    write_aes192_gcm_vector(&dir)?;
    write_aes_vector(&dir)?;
    write_aes_gcm_siv_vector(&dir)?;
    write_argon2id_vector(&dir)?;
    write_aes_kw_vectors(&dir)?;
    write_kmac_vector(&dir)?;
    write_chacha20_poly1305_vector(&dir)?;
    write_x_wing_vector(&dir)?;
    write_hpke_vector(&dir, &keys)?;
    write_hmac_vector(&dir)?;
    write_hkdf_vector(&dir)?;
    write_concat_kdf_vector(&dir)?;
    write_pbkdf2_vector(&dir)?;
    write_hash_vector(&dir)?;
    write_operation_response_vector(&dir)?;
    write_jwk_vector(&dir, &keys)?;
    write_manifest(&dir)
}
