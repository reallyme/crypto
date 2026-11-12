// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![cfg(feature = "ed448")]

use reallyme_crypto::ed448::{require_support, verify, Ed448Error, Ed448Operation};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn software_key_operations_are_explicitly_unavailable() {
    for operation in [
        Ed448Operation::SoftwareKeyGeneration,
        Ed448Operation::SoftwareKeyImport,
    ] {
        assert_eq!(
            require_support(operation),
            Err(Ed448Error::UnsupportedOperation)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg(not(all(feature = "ed448-openssl", not(target_arch = "wasm32"))))]
fn absent_provider_fails_closed_even_for_a_selected_feature() {
    assert_eq!(
        require_support(Ed448Operation::Verify),
        Err(Ed448Error::UnsupportedAlgorithm)
    );
    assert_eq!(
        require_support(Ed448Operation::OpaqueSign),
        Err(Ed448Error::UnsupportedAlgorithm)
    );
    assert_eq!(
        verify(&[0; 57], b"message", &[0; 114]),
        Err(Ed448Error::UnsupportedAlgorithm)
    );
}

#[cfg(all(feature = "ed448-openssl", not(target_arch = "wasm32")))]
mod native {
    use super::{verify, Ed448Error};
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
        fn sign_message(&self, message: &[u8]) -> Result<[u8; 114], Ed448Error> {
            let mut signer = Signer::new_without_digest(&self.private)
                .map_err(|_| Ed448Error::ProviderFailed)?;
            let mut signature = [0; 114];
            let length = signer
                .sign_oneshot(&mut signature, message)
                .map_err(|_| Ed448Error::ProviderFailed)?;
            if length != signature.len() {
                return Err(Ed448Error::ProviderFailed);
            }
            Ok(signature)
        }
    }
    struct Unavailable([u8; 57]);
    impl OpaqueEd448Signer for Unavailable {
        fn public_key(&self) -> &[u8; 57] {
            &self.0
        }
        fn sign_message(&self, _: &[u8]) -> Result<[u8; 114], Ed448Error> {
            Err(Ed448Error::ProviderFailed)
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
                    Err(Ed448Error::InvalidSignature)
                );
                let mut changed = signature.clone();
                changed[0] ^= 1;
                assert_eq!(
                    verify(&public, &message, &changed),
                    Err(Ed448Error::InvalidSignature)
                );
                assert_eq!(
                    sign_with_provider(&Unavailable(provider.public), &message),
                    Err(Ed448Error::ProviderFailed)
                );
                executed += 1;
            } else {
                assert_eq!(
                    verify(&public, &message, &signature),
                    Err(Ed448Error::InvalidSignature)
                );
            }
        }
        assert_eq!(executed, 3);
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
                Err(Ed448Error::InvalidPublicKey)
            );
        }
        for sign in [0, 0x80] {
            for low in [0, 1] {
                let mut small = [0; 57];
                small[0] = low;
                small[56] = sign;
                assert_eq!(
                    verify(&small, b"", &signature),
                    Err(Ed448Error::InvalidPublicKey)
                );
            }
            let mut minus_one = [0xff; 57];
            minus_one[0] = 0xfe;
            minus_one[28] = 0xfe;
            minus_one[56] = sign;
            assert_eq!(
                verify(&minus_one, b"", &signature),
                Err(Ed448Error::InvalidPublicKey)
            );
        }
        for malformed in [vec![], vec![0; 113], vec![0xff; 114], vec![0; 115]] {
            assert_eq!(
                verify(&public, b"", &malformed),
                Err(Ed448Error::InvalidSignature)
            );
        }
    }
}
