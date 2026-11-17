// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![cfg(feature = "native")]

use crypto_core::CryptoError;
use crypto_x448::{
    derive_x448_shared_secret, generate_x448_keypair, generate_x448_keypair_from_seed,
    X448PrivateKey, X448PublicKey, X448_PRIVATE_KEY_LEN, X448_PUBLIC_KEY_LEN,
    X448_SHARED_SECRET_LEN,
};

fn decode_array<const N: usize>(encoded: &str) -> [u8; N] {
    let bytes = hex::decode(encoded).unwrap();
    <[u8; N]>::try_from(bytes).unwrap()
}

#[test]
fn generated_keypairs_agree() -> Result<(), CryptoError> {
    let (private_a, public_a) = generate_x448_keypair()?;
    let (private_b, public_b) = generate_x448_keypair()?;

    let shared_a = derive_x448_shared_secret(&private_a, public_b)?;
    let shared_b = derive_x448_shared_secret(&private_b, public_a)?;

    assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    assert_eq!(shared_a.as_bytes().len(), X448_SHARED_SECRET_LEN);
    Ok(())
}

#[test]
fn rfc7748_vector_matches() -> Result<(), CryptoError> {
    let scalar = decode_array::<X448_PRIVATE_KEY_LEN>(
        "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121\
         700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
    );
    let input = decode_array::<X448_PUBLIC_KEY_LEN>(
        "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9\
         814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
    );
    let expected = decode_array::<X448_SHARED_SECRET_LEN>(
        "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f\
         e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
    );

    let private_key = X448PrivateKey::from_bytes(&scalar)?;
    let public_key = X448PublicKey::from_bytes(&input)?;
    let shared_secret = derive_x448_shared_secret(&private_key, public_key)?;

    assert_eq!(shared_secret.as_bytes(), &expected);
    Ok(())
}

#[test]
fn deterministic_keypair_is_stable() -> Result<(), CryptoError> {
    let seed = [0x5a; X448_PRIVATE_KEY_LEN];
    let (private_a, public_a) = generate_x448_keypair_from_seed(&seed)?;
    let (private_b, public_b) = generate_x448_keypair_from_seed(&seed)?;

    assert_eq!(private_a.as_bytes(), private_b.as_bytes());
    assert_eq!(public_a, public_b);
    Ok(())
}

#[test]
fn invalid_lengths_and_low_order_points_fail_closed() {
    assert!(X448PrivateKey::from_bytes(&[0_u8; X448_PRIVATE_KEY_LEN - 1]).is_err());
    assert!(X448PublicKey::from_bytes(&[0_u8; X448_PUBLIC_KEY_LEN - 1]).is_err());
    assert!(X448PublicKey::from_bytes(&[0_u8; X448_PUBLIC_KEY_LEN]).is_err());
}

#[test]
fn low_order_import_rejects_noncanonical_aliases() {
    let mut prime = [0xff; X448_PUBLIC_KEY_LEN];
    prime[28] = 0xfe;
    let mut minus_one = prime;
    minus_one[0] = 0xfe;
    let mut prime_plus_one = [0xff; X448_PUBLIC_KEY_LEN];
    prime_plus_one[..28].fill(0);
    let mut one = [0; X448_PUBLIC_KEY_LEN];
    one[0] = 1;
    for encoded in [
        [0; X448_PUBLIC_KEY_LEN],
        one,
        minus_one,
        prime,
        prime_plus_one,
    ] {
        assert_eq!(
            X448PublicKey::from_bytes(&encoded).err(),
            Some(CryptoError::PRIMITIVE_INVALID_KEY),
        );
    }
}

#[test]
fn contributory_noncanonical_coordinate_still_agrees() -> Result<(), CryptoError> {
    // RFC 7748 requires accepting noncanonical coordinates modulo p. p+2
    // must remain usable even though the neighboring p and p+1 are rejected.
    let mut noncanonical = [0xff; X448_PUBLIC_KEY_LEN];
    noncanonical[..28].fill(0);
    noncanonical[0] = 1;
    let mut canonical = [0; X448_PUBLIC_KEY_LEN];
    canonical[0] = 2;
    let private_key = X448PrivateKey::from_bytes(&[0x73; X448_PRIVATE_KEY_LEN])?;
    let from_noncanonical =
        derive_x448_shared_secret(&private_key, X448PublicKey::from_bytes(&noncanonical)?)?;
    let from_canonical =
        derive_x448_shared_secret(&private_key, X448PublicKey::from_bytes(&canonical)?)?;
    assert_eq!(from_noncanonical.as_bytes(), from_canonical.as_bytes());
    Ok(())
}
