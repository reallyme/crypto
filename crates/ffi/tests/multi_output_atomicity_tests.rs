// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rejected output capacities must leave every caller buffer unchanged.

#![allow(missing_docs, unsafe_code, clippy::expect_used)]

use crypto_ffi::ed25519;
use crypto_ffi::ml_dsa_44;
use crypto_ffi::ml_dsa_65;
use crypto_ffi::ml_dsa_87;
use crypto_ffi::ml_kem_1024;
use crypto_ffi::ml_kem_512;
use crypto_ffi::ml_kem_768;
use crypto_ffi::p256;
use crypto_ffi::p384;
use crypto_ffi::p521;
use crypto_ffi::secp256k1;
use crypto_ffi::slh_dsa;
use crypto_ffi::status::{CryptoStatus, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_OK};
use crypto_ffi::x25519;
use crypto_ffi::x_wing;
use zeroize::Zeroizing;

const SENTINEL: u8 = 0xa5;
type Generate = unsafe extern "C" fn(*mut u8, usize, *mut u8, usize) -> CryptoStatus;
type Derive =
    unsafe extern "C" fn(*const u8, usize, *mut u8, usize, *mut u8, usize) -> CryptoStatus;

struct KeypairCase {
    name: &'static str,
    generate: Generate,
    derive: Option<Derive>,
    public_len: usize,
    secret_len: usize,
    seed_len: usize,
}

fn keypairs() -> [KeypairCase; 14] {
    [
        KeypairCase {
            name: "p256",
            generate: p256::rm_crypto_p256_generate_keypair,
            derive: Some(p256::rm_crypto_p256_generate_keypair_from_secret_key),
            public_len: p256::P256_PUBLIC_KEY_COMPRESSED_LEN,
            secret_len: p256::P256_SECRET_KEY_LEN,
            seed_len: p256::P256_SECRET_KEY_LEN,
        },
        KeypairCase {
            name: "p384",
            generate: p384::rm_crypto_p384_generate_keypair,
            derive: Some(p384::rm_crypto_p384_generate_keypair_from_secret_key),
            public_len: p384::P384_PUBLIC_KEY_COMPRESSED_LEN,
            secret_len: p384::P384_SECRET_KEY_LEN,
            seed_len: p384::P384_SECRET_KEY_LEN,
        },
        KeypairCase {
            name: "p521",
            generate: p521::rm_crypto_p521_generate_keypair,
            derive: Some(p521::rm_crypto_p521_generate_keypair_from_secret_key),
            public_len: p521::P521_PUBLIC_KEY_COMPRESSED_LEN,
            secret_len: p521::P521_SECRET_KEY_LEN,
            seed_len: p521::P521_SECRET_KEY_LEN,
        },
        KeypairCase {
            name: "secp256k1",
            generate: secp256k1::rm_crypto_secp256k1_generate_keypair,
            derive: Some(secp256k1::rm_crypto_secp256k1_generate_keypair_from_secret_key),
            public_len: secp256k1::SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
            secret_len: secp256k1::SECP256K1_SECRET_KEY_LEN,
            seed_len: secp256k1::SECP256K1_SECRET_KEY_LEN,
        },
        KeypairCase {
            name: "ed25519",
            generate: ed25519::rm_crypto_ed25519_generate_keypair,
            derive: Some(ed25519::rm_crypto_ed25519_generate_keypair_from_seed),
            public_len: ed25519::ED25519_PUBLIC_KEY_LEN,
            secret_len: ed25519::ED25519_SECRET_KEY_LEN,
            seed_len: ed25519::ED25519_SECRET_KEY_LEN,
        },
        KeypairCase {
            name: "x25519",
            generate: x25519::rm_crypto_x25519_generate_keypair,
            derive: Some(x25519::rm_crypto_x25519_generate_keypair_from_seed),
            public_len: x25519::X25519_PUBLIC_KEY_LEN,
            secret_len: x25519::X25519_SECRET_KEY_LEN,
            seed_len: x25519::X25519_SECRET_KEY_LEN,
        },
        KeypairCase {
            name: "ml_dsa_44",
            generate: ml_dsa_44::rm_crypto_ml_dsa_44_generate_keypair,
            derive: Some(ml_dsa_44::rm_crypto_ml_dsa_44_generate_keypair_from_seed),
            public_len: ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN,
            secret_len: ml_dsa_44::ML_DSA_44_SECRET_SEED_LEN,
            seed_len: ml_dsa_44::ML_DSA_44_SECRET_SEED_LEN,
        },
        KeypairCase {
            name: "ml_dsa_65",
            generate: ml_dsa_65::rm_crypto_ml_dsa_65_generate_keypair,
            derive: Some(ml_dsa_65::rm_crypto_ml_dsa_65_generate_keypair_from_seed),
            public_len: ml_dsa_65::ML_DSA_65_PUBLIC_KEY_LEN,
            secret_len: ml_dsa_65::ML_DSA_65_SECRET_SEED_LEN,
            seed_len: ml_dsa_65::ML_DSA_65_SECRET_SEED_LEN,
        },
        KeypairCase {
            name: "ml_dsa_87",
            generate: ml_dsa_87::rm_crypto_ml_dsa_87_generate_keypair,
            derive: Some(ml_dsa_87::rm_crypto_ml_dsa_87_generate_keypair_from_seed),
            public_len: ml_dsa_87::ML_DSA_87_PUBLIC_KEY_LEN,
            secret_len: ml_dsa_87::ML_DSA_87_SECRET_SEED_LEN,
            seed_len: ml_dsa_87::ML_DSA_87_SECRET_SEED_LEN,
        },
        KeypairCase {
            name: "slh_dsa",
            generate: slh_dsa::rm_crypto_slh_dsa_sha2_128s_generate_keypair,
            // SLH-DSA has three separate seed inputs, tested below.
            derive: None,
            public_len: slh_dsa::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN,
            secret_len: slh_dsa::SLH_DSA_SHA2_128S_SECRET_KEY_LEN,
            seed_len: slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN,
        },
        KeypairCase {
            name: "ml_kem_512",
            generate: ml_kem_512::rm_crypto_ml_kem_512_generate_keypair,
            derive: Some(ml_kem_512::rm_crypto_ml_kem_512_generate_keypair_from_seed),
            public_len: ml_kem_512::ML_KEM_512_PUBLIC_KEY_LEN,
            secret_len: ml_kem_512::ML_KEM_512_SECRET_KEY_LEN,
            seed_len: ml_kem_512::ML_KEM_512_SECRET_KEY_LEN,
        },
        KeypairCase {
            name: "ml_kem_768",
            generate: ml_kem_768::rm_crypto_ml_kem_768_generate_keypair,
            derive: Some(ml_kem_768::rm_crypto_ml_kem_768_generate_keypair_from_seed),
            public_len: ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN,
            secret_len: ml_kem_768::ML_KEM_768_SECRET_KEY_LEN,
            seed_len: ml_kem_768::ML_KEM_768_SECRET_KEY_LEN,
        },
        KeypairCase {
            name: "ml_kem_1024",
            generate: ml_kem_1024::rm_crypto_ml_kem_1024_generate_keypair,
            derive: Some(ml_kem_1024::rm_crypto_ml_kem_1024_generate_keypair_from_seed),
            public_len: ml_kem_1024::ML_KEM_1024_PUBLIC_KEY_LEN,
            secret_len: ml_kem_1024::ML_KEM_1024_SECRET_KEY_LEN,
            seed_len: ml_kem_1024::ML_KEM_1024_SECRET_KEY_LEN,
        },
        KeypairCase {
            name: "x_wing",
            generate: x_wing::rm_crypto_x_wing_768_generate_keypair,
            derive: None,
            public_len: x_wing::X_WING_768_PUBLIC_KEY_LEN,
            secret_len: x_wing::X_WING_SECRET_KEY_LEN,
            seed_len: x_wing::X_WING_SECRET_KEY_LEN,
        },
    ]
}

#[test]
fn every_keypair_export_preserves_both_outputs_when_either_is_short() {
    for case in keypairs() {
        let seed = Zeroizing::new(vec![1u8; case.seed_len]);
        for (public_len, secret_len) in [
            (
                case.public_len.checked_sub(1).expect("nonempty public key"),
                case.secret_len,
            ),
            (
                case.public_len,
                case.secret_len.checked_sub(1).expect("nonempty secret key"),
            ),
        ] {
            let mut public = vec![SENTINEL; case.public_len];
            let mut secret = Zeroizing::new(vec![SENTINEL; case.secret_len]);
            // SAFETY: Separate live allocations cover both declared output
            // lengths. Rejection must precede any copy into these buffers.
            let status = unsafe {
                (case.generate)(
                    public.as_mut_ptr(),
                    public_len,
                    secret.as_mut_ptr(),
                    secret_len,
                )
            };
            assert_eq!(status, CRYPTO_BUFFER_TOO_SMALL, "{}", case.name);
            assert!(public.iter().all(|byte| *byte == SENTINEL), "{}", case.name);
            assert!(secret.iter().all(|byte| *byte == SENTINEL), "{}", case.name);
            if let Some(derive) = case.derive {
                // SAFETY: The seed is initialized and immutable. Both outputs
                // remain live, writable, and disjoint from each other and it.
                let status = unsafe {
                    derive(
                        seed.as_ptr(),
                        seed.len(),
                        public.as_mut_ptr(),
                        public_len,
                        secret.as_mut_ptr(),
                        secret_len,
                    )
                };
                assert_eq!(status, CRYPTO_BUFFER_TOO_SMALL, "{}", case.name);
                assert!(public.iter().all(|byte| *byte == SENTINEL), "{}", case.name);
                assert!(secret.iter().all(|byte| *byte == SENTINEL), "{}", case.name);
            }
        }
    }
}

#[test]
fn slh_dsa_supplied_keypair_rejects_short_outputs_atomically() {
    let sk_seed = Zeroizing::new([0x11; slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN]);
    let sk_prf = Zeroizing::new([0x22; slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN]);
    let pk_seed = Zeroizing::new([0x33; slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN]);
    for (public_len, secret_len) in [
        (
            slh_dsa::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN
                .checked_sub(1)
                .expect("nonempty public key"),
            slh_dsa::SLH_DSA_SHA2_128S_SECRET_KEY_LEN,
        ),
        (
            slh_dsa::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN,
            slh_dsa::SLH_DSA_SHA2_128S_SECRET_KEY_LEN
                .checked_sub(1)
                .expect("nonempty secret key"),
        ),
    ] {
        let mut public = [SENTINEL; slh_dsa::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN];
        let mut secret = Zeroizing::new([SENTINEL; slh_dsa::SLH_DSA_SHA2_128S_SECRET_KEY_LEN]);
        // SAFETY: The initialized seeds are live and immutable; both outputs
        // are separate writable allocations covering their declared lengths.
        let status = unsafe {
            slh_dsa::rm_crypto_slh_dsa_sha2_128s_derive_keypair(
                sk_seed.as_ptr(),
                sk_seed.len(),
                sk_prf.as_ptr(),
                sk_prf.len(),
                pk_seed.as_ptr(),
                pk_seed.len(),
                public.as_mut_ptr(),
                public_len,
                secret.as_mut_ptr(),
                secret_len,
            )
        };
        assert_eq!(status, CRYPTO_BUFFER_TOO_SMALL);
        assert!(public.iter().all(|byte| *byte == SENTINEL));
        assert!(secret.iter().all(|byte| *byte == SENTINEL));
    }
}

type Encapsulate =
    unsafe extern "C" fn(*const u8, usize, *mut u8, usize, *mut u8, usize) -> CryptoStatus;
#[cfg(feature = "test-vectors")]
type EncapsulateDeterministic = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut u8,
    usize,
) -> CryptoStatus;

struct KemCase {
    name: &'static str,
    generate: Generate,
    encapsulate: Encapsulate,
    public_len: usize,
    secret_len: usize,
    ciphertext_len: usize,
    shared_len: usize,
    #[cfg(feature = "test-vectors")]
    deterministic: EncapsulateDeterministic,
    #[cfg(feature = "test-vectors")]
    seed_len: usize,
}

fn kems() -> [KemCase; 4] {
    [
        KemCase {
            name: "ml_kem_512",
            generate: ml_kem_512::rm_crypto_ml_kem_512_generate_keypair,
            encapsulate: ml_kem_512::rm_crypto_ml_kem_512_encapsulate,
            public_len: ml_kem_512::ML_KEM_512_PUBLIC_KEY_LEN,
            secret_len: ml_kem_512::ML_KEM_512_SECRET_KEY_LEN,
            ciphertext_len: ml_kem_512::ML_KEM_512_CIPHERTEXT_LEN,
            shared_len: ml_kem_512::ML_KEM_512_SHARED_SECRET_LEN,
            #[cfg(feature = "test-vectors")]
            deterministic: ml_kem_512::rm_crypto_ml_kem_512_encapsulate_derand,
            #[cfg(feature = "test-vectors")]
            seed_len: ml_kem_512::ML_KEM_512_ENCAPS_RANDOMNESS_LEN,
        },
        KemCase {
            name: "ml_kem_768",
            generate: ml_kem_768::rm_crypto_ml_kem_768_generate_keypair,
            encapsulate: ml_kem_768::rm_crypto_ml_kem_768_encapsulate,
            public_len: ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN,
            secret_len: ml_kem_768::ML_KEM_768_SECRET_KEY_LEN,
            ciphertext_len: ml_kem_768::ML_KEM_768_CIPHERTEXT_LEN,
            shared_len: ml_kem_768::ML_KEM_768_SHARED_SECRET_LEN,
            #[cfg(feature = "test-vectors")]
            deterministic: ml_kem_768::rm_crypto_ml_kem_768_encapsulate_derand,
            #[cfg(feature = "test-vectors")]
            seed_len: ml_kem_768::ML_KEM_768_ENCAPS_RANDOMNESS_LEN,
        },
        KemCase {
            name: "ml_kem_1024",
            generate: ml_kem_1024::rm_crypto_ml_kem_1024_generate_keypair,
            encapsulate: ml_kem_1024::rm_crypto_ml_kem_1024_encapsulate,
            public_len: ml_kem_1024::ML_KEM_1024_PUBLIC_KEY_LEN,
            secret_len: ml_kem_1024::ML_KEM_1024_SECRET_KEY_LEN,
            ciphertext_len: ml_kem_1024::ML_KEM_1024_CIPHERTEXT_LEN,
            shared_len: ml_kem_1024::ML_KEM_1024_SHARED_SECRET_LEN,
            #[cfg(feature = "test-vectors")]
            deterministic: ml_kem_1024::rm_crypto_ml_kem_1024_encapsulate_derand,
            #[cfg(feature = "test-vectors")]
            seed_len: ml_kem_1024::ML_KEM_1024_ENCAPS_RANDOMNESS_LEN,
        },
        KemCase {
            name: "x_wing",
            generate: x_wing::rm_crypto_x_wing_768_generate_keypair,
            encapsulate: x_wing::rm_crypto_x_wing_768_encapsulate,
            public_len: x_wing::X_WING_768_PUBLIC_KEY_LEN,
            secret_len: x_wing::X_WING_SECRET_KEY_LEN,
            ciphertext_len: x_wing::X_WING_768_CIPHERTEXT_LEN,
            shared_len: x_wing::X_WING_SHARED_SECRET_LEN,
            #[cfg(feature = "test-vectors")]
            deterministic: x_wing::rm_crypto_x_wing_768_encapsulate_derand,
            #[cfg(feature = "test-vectors")]
            seed_len: x_wing::X_WING_ENCAPS_SEED_LEN,
        },
    ]
}

#[test]
fn every_encapsulation_export_preserves_both_outputs_when_either_is_short() {
    for case in kems() {
        let mut public = vec![0u8; case.public_len];
        let mut secret = Zeroizing::new(vec![0u8; case.secret_len]);
        // SAFETY: Both outputs are live, sized for the selected algorithm,
        // exclusively writable, and disjoint for the duration of the call.
        assert_eq!(
            unsafe {
                (case.generate)(
                    public.as_mut_ptr(),
                    public.len(),
                    secret.as_mut_ptr(),
                    secret.len(),
                )
            },
            CRYPTO_OK
        );
        for (ciphertext_capacity, shared_capacity) in [
            (
                case.ciphertext_len
                    .checked_sub(1)
                    .expect("nonempty ciphertext"),
                case.shared_len,
            ),
            (
                case.ciphertext_len,
                case.shared_len
                    .checked_sub(1)
                    .expect("nonempty shared secret"),
            ),
        ] {
            let mut ciphertext = vec![SENTINEL; case.ciphertext_len];
            let mut shared = Zeroizing::new(vec![SENTINEL; case.shared_len]);
            // SAFETY: The public input remains initialized and immutable.
            // Both outputs are separate live allocations of the declared sizes.
            let status = unsafe {
                (case.encapsulate)(
                    public.as_ptr(),
                    public.len(),
                    ciphertext.as_mut_ptr(),
                    ciphertext_capacity,
                    shared.as_mut_ptr(),
                    shared_capacity,
                )
            };
            assert_eq!(status, CRYPTO_BUFFER_TOO_SMALL, "{}", case.name);
            assert!(
                ciphertext.iter().all(|byte| *byte == SENTINEL),
                "{}",
                case.name
            );
            assert!(shared.iter().all(|byte| *byte == SENTINEL), "{}", case.name);
            #[cfg(feature = "test-vectors")]
            {
                let seed = Zeroizing::new(vec![1u8; case.seed_len]);
                // SAFETY: The seed and public input remain immutable, alive,
                // and disjoint from both exclusively writable output ranges.
                let status = unsafe {
                    (case.deterministic)(
                        public.as_ptr(),
                        public.len(),
                        seed.as_ptr(),
                        seed.len(),
                        ciphertext.as_mut_ptr(),
                        ciphertext_capacity,
                        shared.as_mut_ptr(),
                        shared_capacity,
                    )
                };
                assert_eq!(status, CRYPTO_BUFFER_TOO_SMALL, "{}", case.name);
                assert!(
                    ciphertext.iter().all(|byte| *byte == SENTINEL),
                    "{}",
                    case.name
                );
                assert!(shared.iter().all(|byte| *byte == SENTINEL), "{}", case.name);
            }
        }
    }
}
