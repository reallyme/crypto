// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{b64u, ecdsa_invalid_encodings, vectors_dir, VectorGenError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

#[test]
fn shared_ecdsa_negative_vectors_are_reproducible() -> Result<(), VectorGenError> {
    for (file, signature_field) in [
        ("p256.json", "ecdsa_signature_der"),
        ("p384.json", "signature_der"),
        ("p521.json", "signature_der"),
    ] {
        let contents =
            std::fs::read(vectors_dir()?.join(file)).map_err(|_| VectorGenError::EcdsaEncoding)?;
        let vector: serde_json::Value =
            serde_json::from_slice(&contents).map_err(|_| VectorGenError::EcdsaEncoding)?;
        let decode = |name: &str| {
            vector
                .get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or(VectorGenError::EcdsaEncoding)
                .and_then(|text| {
                    URL_SAFE_NO_PAD
                        .decode(text)
                        .map_err(|_| VectorGenError::EcdsaEncoding)
                })
        };
        let signature = decode(signature_field)?;
        let public_key = decode("public_key_uncompressed")?;
        let generated = serde_json::to_value(ecdsa_invalid_encodings(&signature, &public_key)?)
            .map_err(|_| VectorGenError::SerializeJson)?;
        let fields = generated.as_object().ok_or(VectorGenError::EcdsaEncoding)?;
        assert_eq!(fields.len(), 5);
        for (name, value) in fields {
            assert_eq!(vector.get(name), Some(value), "{file}: {name}");
        }
        // Hybrid aliases preserve the complete coordinates; one of the
        // two tags even agrees with the point's parity, yet both must fail.
        let mut canonical = decode("public_key_hybrid_even")?;
        if let Some(tag) = canonical.first_mut() {
            *tag = 0x04;
        }
        assert_eq!(b64u(&canonical), b64u(&public_key));
    }
    Ok(())
}
