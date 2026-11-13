// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![cfg(feature = "ed448")]

use crypto_core::CryptoError;
use reallyme_crypto::ed448::{require_support, verify, Ed448Key, Ed448Operation};
use reallyme_crypto::key_random::KeyRng;
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("data/ed448_rfc8032.json")).unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn software_key_operations_are_available() {
    for operation in [
        Ed448Operation::SoftwareKeyGeneration,
        Ed448Operation::SoftwareKeyImport,
    ] {
        assert_eq!(require_support(operation), Ok(()));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn verification_and_opaque_signing_are_available() {
    assert_eq!(require_support(Ed448Operation::Verify), Ok(()));
    assert_eq!(require_support(Ed448Operation::OpaqueSign), Ok(()));
    assert_eq!(
        verify(&[0; 57], b"message", &[0; 114]),
        Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rfc8032_software_generation_and_signing_known_answers_execute() {
    let fixture = vectors();
    let mut executed = 0;
    for v in fixture["vectors"].as_array().unwrap() {
        let public = bytes(&v["public"]);
        let message = bytes(&v["message"]);
        let signature = bytes(&v["signature"]);
        let key = Ed448Key::import(&bytes(&v["seed"])).unwrap();
        assert_eq!(key.public_key().as_slice(), public);
        if v["prehash"] == "false" && v["context"] == "" {
            assert_eq!(key.sign(&message).unwrap().as_slice(), signature);
            verify(&public, &message, &signature).unwrap();
            let mut changed = message.clone();
            changed.push(0);
            assert_eq!(
                verify(&public, &changed, &signature),
                Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
            );
            executed += 1;
        } else {
            assert_eq!(
                verify(&public, &message, &signature),
                Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
            );
            assert_ne!(key.sign(&message).unwrap().as_slice(), signature);
        }
    }
    assert_eq!(executed, 8);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn signature_scalar_unused_bits_and_order_are_checked_independently() {
    let fixture = vectors();
    let v = &fixture["vectors"][0];
    let public = bytes(&v["public"]);
    let signature = bytes(&v["signature"]);
    for index in [112, 113] {
        for value in [1, 0x40, 0x80, 0xff] {
            let mut changed = signature.clone();
            if index == 112 {
                changed[index] |= value & 0xc0;
                if value & 0xc0 == 0 {
                    continue;
                }
            } else {
                changed[index] = value;
            }
            assert_eq!(
                verify(&public, b"", &changed),
                Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
            );
        }
    }
    let mut order = hex::decode("f34458ab92c27823558fc8d722c26c219036d6ae49db44c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00").unwrap();
    assert_eq!(order.len(), 57);
    let mut changed = signature.clone();
    changed[57..].copy_from_slice(&order);
    assert_eq!(
        verify(&public, b"", &changed),
        Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
    order.fill(0xff);
    changed[57..].copy_from_slice(&order);
    assert_eq!(
        verify(&public, b"", &changed),
        Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_points_and_all_truncated_signatures_are_rejected() {
    let fixture = vectors();
    let v = &fixture["vectors"][0];
    let public = bytes(&v["public"]);
    let signature = bytes(&v["signature"]);
    for length in 0..signature.len() {
        assert_eq!(
            verify(&public, b"", &signature[..length]),
            Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
        );
    }
    for length in 0..public.len() {
        assert_eq!(
            verify(&public[..length], b"", &signature),
            Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
        );
    }
    for length in [115, 16_384] {
        assert_eq!(
            verify(&public, b"", &vec![0; length]),
            Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
        );
    }
    for length in [58, 16_384] {
        assert_eq!(
            verify(&vec![0; length], b"", &signature),
            Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
        );
    }
    for sign in [0, 0x80] {
        for low in [0, 1] {
            let mut small = [0; 57];
            small[0] = low;
            small[56] = sign;
            assert_eq!(
                verify(&small, b"", &signature),
                Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
            );
        }
        let mut minus_one = [0xff; 57];
        minus_one[0] = 0xfe;
        minus_one[28] = 0xfe;
        minus_one[56] = sign;
        assert_eq!(
            verify(&minus_one, b"", &signature),
            Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
        );
    }
    for invalid in [[0xff; 57], [0x7f; 57]] {
        assert_eq!(
            verify(&invalid, b"", &signature),
            Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
        );
        let mut changed = signature.clone();
        changed[..57].copy_from_slice(&invalid);
        assert_eq!(
            verify(&public, b"", &changed),
            Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
        );
    }
    let mut changed = public.clone();
    changed[56] |= 1;
    assert_eq!(
        verify(&changed, b"", &signature),
        Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    );
}

struct FixedEntropy(u8);
impl KeyRng for FixedEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        destination.fill(self.0);
        Ok(())
    }
}
struct PartialFailure;
impl KeyRng for PartialFailure {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        destination[..17].fill(0xa5);
        Err(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn key_owner_handles_entropy_failures_lengths_and_explicit_cleanup() {
    fn clearing_owner<T: ZeroizeOnDrop>() {}
    clearing_owner::<Ed448Key>();
    let system_key = Ed448Key::generate().unwrap();
    assert_ne!(system_key.public_key(), &[0; 57]);
    for length in [0, 1, 56, 58, 4096] {
        assert!(matches!(
            Ed448Key::import(&vec![0; length]),
            Err(CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)
        ));
    }
    assert!(matches!(
        Ed448Key::generate_with_rng(&mut PartialFailure),
        Err(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    ));
    let mut key = Ed448Key::generate_with_rng(&mut FixedEntropy(0)).unwrap();
    let imported = Ed448Key::import(&[0; 57]).unwrap();
    assert_eq!(key.public_key(), imported.public_key());
    let signature = key.sign(b"zero is a valid seed").unwrap();
    verify(key.public_key(), b"zero is a valid seed", &signature).unwrap();
    key.zeroize();
    assert_eq!(
        key.sign(b"after cleanup"),
        Err(CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)
    );
    key.zeroize();
    assert_eq!(
        key.sign(b"after repeated cleanup"),
        Err(CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn portable_opaque_provider_binds_message_key_and_typed_failures() {
    use reallyme_crypto::ed448::{sign_with_provider, OpaqueEd448Signer};
    struct NonExporting {
        key: Ed448Key,
        public: [u8; 57],
        fail: bool,
        wrong_message: bool,
    }
    impl OpaqueEd448Signer for NonExporting {
        fn public_key(&self) -> &[u8; 57] {
            &self.public
        }
        fn sign_message(&self, message: &[u8]) -> Result<[u8; 114], CryptoError> {
            if self.fail {
                return Err(CryptoError::BACKEND_INTERNAL);
            }
            self.key.sign(if self.wrong_message {
                b"different message"
            } else {
                message
            })
        }
    }
    let fixture = vectors();
    let v = &fixture["vectors"][0];
    let key = Ed448Key::import(&bytes(&v["seed"])).unwrap();
    let public = *key.public_key();
    let mut provider = NonExporting {
        key,
        public,
        fail: false,
        wrong_message: false,
    };
    assert_eq!(
        sign_with_provider(&provider, b"").unwrap().as_slice(),
        bytes(&v["signature"])
    );
    provider.fail = true;
    assert_eq!(
        sign_with_provider(&provider, b""),
        Err(CryptoError::BACKEND_INTERNAL)
    );
    provider.fail = false;
    provider.wrong_message = true;
    assert_eq!(
        sign_with_provider(&provider, b""),
        Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
    provider.wrong_message = false;
    provider.public = *Ed448Key::import(&[0; 57]).unwrap().public_key();
    assert_eq!(
        sign_with_provider(&provider, b""),
        Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
}

#[cfg(all(feature = "ed448-openssl", not(target_arch = "wasm32")))]
mod native {
    use super::{verify, CryptoError};
    use openssl::{
        pkey::{Id, PKey, Private},
        sign::Signer,
    };
    use reallyme_crypto::ed448::{sign_with_provider, OpaqueEd448Signer};
    use serde_json::Value;

    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().unwrap()).unwrap()
    }

    // The fixed RFC seeds are public test data. This test provider exposes no
    // private-key export through the production signing trait; it is not a
    // proposed software private-key implementation for library consumers.
    struct NonExporting {
        private: PKey<Private>,
        public: [u8; 57],
    }
    impl OpaqueEd448Signer for NonExporting {
        fn public_key(&self) -> &[u8; 57] {
            &self.public
        }
        fn sign_message(&self, message: &[u8]) -> Result<[u8; 114], CryptoError> {
            let mut signer = Signer::new_without_digest(&self.private)
                .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
            let mut signature = [0; 114];
            let length = signer
                .sign_oneshot(&mut signature, message)
                .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
            if length != signature.len() {
                return Err(CryptoError::BACKEND_INTERNAL);
            }
            Ok(signature)
        }
    }
    struct Unavailable([u8; 57]);
    impl OpaqueEd448Signer for Unavailable {
        fn public_key(&self) -> &[u8; 57] {
            &self.0
        }
        fn sign_message(&self, _: &[u8]) -> Result<[u8; 114], CryptoError> {
            Err(CryptoError::BACKEND_INTERNAL)
        }
    }

    #[test]
    fn rfc8032_ordinary_vectors_and_non_exporting_signing_execute() {
        let fixture: Value = serde_json::from_str(include_str!("data/ed448_rfc8032.json")).unwrap();
        let mut executed = 0;
        for v in fixture["vectors"].as_array().unwrap() {
            let public = bytes(&v["public"]);
            let message = bytes(&v["message"]);
            let signature = bytes(&v["signature"]);
            if v["prehash"] == "false" && v["context"] == "" {
                let private =
                    PKey::private_key_from_raw_bytes(&bytes(&v["seed"]), Id::ED448).unwrap();
                let provider = NonExporting {
                    private,
                    public: public.as_slice().try_into().unwrap(),
                };
                assert_eq!(provider.private.raw_public_key().unwrap(), public);
                assert_eq!(
                    sign_with_provider(&provider, &message).unwrap().as_slice(),
                    signature
                );
                verify(&public, &message, &signature).unwrap();
                let mut changed = message.clone();
                changed.push(0);
                assert_eq!(
                    verify(&public, &changed, &signature),
                    Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
                );
                let mut changed = signature.clone();
                changed[0] ^= 1;
                assert_eq!(
                    verify(&public, &message, &changed),
                    Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
                );
                assert_eq!(
                    sign_with_provider(&Unavailable(provider.public), &message),
                    Err(CryptoError::BACKEND_INTERNAL)
                );
                executed += 1;
            } else {
                assert_eq!(
                    verify(&public, &message, &signature),
                    Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
                );
            }
        }
        assert_eq!(executed, 8);
    }

    #[test]
    fn malformed_encodings_small_order_keys_and_signatures_are_rejected() {
        let fixture: Value = serde_json::from_str(include_str!("data/ed448_rfc8032.json")).unwrap();
        let v = &fixture["vectors"][0];
        let public = bytes(&v["public"]);
        let signature = bytes(&v["signature"]);
        for malformed in [vec![], vec![0; 56], vec![0xff; 57], vec![0; 58]] {
            assert_eq!(
                verify(&malformed, b"", &signature),
                Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
            );
        }
        for sign in [0, 0x80] {
            for low in [0, 1] {
                let mut small = [0; 57];
                small[0] = low;
                small[56] = sign;
                assert_eq!(
                    verify(&small, b"", &signature),
                    Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
                );
            }
            let mut minus_one = [0xff; 57];
            minus_one[0] = 0xfe;
            minus_one[28] = 0xfe;
            minus_one[56] = sign;
            assert_eq!(
                verify(&minus_one, b"", &signature),
                Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
            );
        }
        for malformed in [vec![], vec![0; 113], vec![0xff; 114], vec![0; 115]] {
            assert_eq!(
                verify(&public, b"", &malformed),
                Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
            );
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn canonical_entropy_errors_are_not_collapsed() {
    struct Failure;
    impl KeyRng for Failure {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination.fill(0xa5);
            Err(CryptoError::BACKEND_INVALID_STATE)
        }
    }
    assert_eq!(
        Ed448Key::generate_with_rng(&mut Failure).err(),
        Some(CryptoError::BACKEND_INVALID_STATE)
    );
}
