// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn x25519_vector_invariants() -> Result<(), VectorTestError> {
    let v = load("x25519.json")?;
    let sk = b64u_to_bytes(field_string(&v, "secret_key")?)?;
    let pk = b64u_to_bytes(field_string(&v, "public_key")?)?;
    let peer_sk = b64u_to_bytes(field_string(&v, "peer_secret_key")?)?;
    let peer_pk = b64u_to_bytes(field_string(&v, "peer_public_key")?)?;
    let expected_shared_secret = b64u_to_bytes(field_string(&v, "shared_secret")?)?;

    assert_eq!(sk.len(), 32);
    assert_eq!(pk.len(), 32);
    assert_eq!(peer_sk.len(), 32);
    assert_eq!(peer_pk.len(), 32);
    assert_eq!(expected_shared_secret.len(), 32);

    let ss =
        derive_x25519_shared_secret(&sk, &peer_pk).map_err(|_| VectorTestError::X25519Derive)?;
    let peer_ss =
        derive_x25519_shared_secret(&peer_sk, &pk).map_err(|_| VectorTestError::X25519Derive)?;
    assert_eq!(*ss, expected_shared_secret);
    assert_eq!(*peer_ss, expected_shared_secret);
    Ok(())
}

fn verify_x_wing_case<Keypair, Encapsulate, Decapsulate>(
    v: &Value,
    public_key_len: usize,
    ciphertext_len: usize,
    keypair: Keypair,
    encapsulate: Encapsulate,
    decapsulate: Decapsulate,
) -> Result<(), VectorTestError>
where
    Keypair: Fn(&[u8]) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), crypto_core::CryptoError>,
    Encapsulate: Fn(
        &[u8],
        &[u8],
    )
        -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), crypto_core::CryptoError>,
    Decapsulate: Fn(&[u8], &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, crypto_core::CryptoError>,
{
    assert_eq!(field_string(v, "secret_key_format")?, "x-wing-seed");
    let secret_key = b64u_to_bytes(field_string(v, "secret_key")?)?;
    let public_key = b64u_to_bytes(field_string(v, "public_key")?)?;
    let encaps_seed = b64u_to_bytes(field_string(v, "encaps_seed")?)?;
    let ciphertext = b64u_to_bytes(field_string(v, "ciphertext")?)?;
    let shared_secret = b64u_to_bytes(field_string(v, "shared_secret")?)?;

    assert_eq!(secret_key.len(), 32);
    assert_eq!(public_key.len(), public_key_len);
    assert_eq!(encaps_seed.len(), 64);
    assert_eq!(ciphertext.len(), ciphertext_len);
    assert_eq!(shared_secret.len(), 32);

    let (derived_public, _derived_secret) =
        keypair(&secret_key).map_err(|_| VectorTestError::XWingOperation)?;
    if derived_public != public_key {
        return Err(VectorTestError::XWingMismatch);
    }

    let (derived_ciphertext, derived_shared_secret) =
        encapsulate(&public_key, &encaps_seed).map_err(|_| VectorTestError::XWingOperation)?;
    if derived_ciphertext != ciphertext || derived_shared_secret.as_slice() != shared_secret {
        return Err(VectorTestError::XWingMismatch);
    }

    let decapsulated =
        decapsulate(&ciphertext, &secret_key).map_err(|_| VectorTestError::XWingOperation)?;
    if decapsulated.as_slice() != shared_secret {
        return Err(VectorTestError::XWingMismatch);
    }
    Ok(())
}

#[test]
fn x_wing_vectors_match_workspace_primitives() -> Result<(), VectorTestError> {
    let v = load("x_wing.json")?;
    verify_x_wing_case(
        object_field(&v, "x_wing_768")?,
        1216,
        1120,
        generate_x_wing_768_keypair_derand,
        x_wing_768_encapsulate_derand,
        x_wing_768_decapsulate,
    )?;
    Ok(())
}
