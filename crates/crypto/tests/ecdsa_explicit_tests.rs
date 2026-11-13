// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used, clippy::panic)]
#![cfg(feature = "ecdsa-explicit")]

use reallyme_crypto::ecdsa_explicit::{
    der_to_fixed, fixed_to_der, sign_with_provider, validate_public_key, verify, EcdsaCurve,
    EcdsaEncoding, EcdsaError, EcdsaHash, EcdsaInput, EcdsaKey, OpaqueEcdsaSigner,
};
use secrecy::ExposeSecret;
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}
fn curve(value: &Value) -> EcdsaCurve {
    match value.as_str().unwrap() {
        "P256" => EcdsaCurve::P256,
        "P384" => EcdsaCurve::P384,
        "P521" => EcdsaCurve::P521,
        "BrainpoolP256r1" => EcdsaCurve::BrainpoolP256r1,
        "BrainpoolP320r1" => EcdsaCurve::BrainpoolP320r1,
        "BrainpoolP384r1" => EcdsaCurve::BrainpoolP384r1,
        "BrainpoolP512r1" => EcdsaCurve::BrainpoolP512r1,
        _ => panic!("invalid public fixture"),
    }
}
fn hash(value: &Value) -> EcdsaHash {
    match value.as_str().unwrap() {
        "sha256" => EcdsaHash::Sha256,
        "sha384" => EcdsaHash::Sha384,
        "sha512" => EcdsaHash::Sha512,
        _ => panic!("invalid public fixture"),
    }
}
fn portable(curve: EcdsaCurve) -> bool {
    matches!(
        curve,
        EcdsaCurve::P256 | EcdsaCurve::P384 | EcdsaCurve::P521
    )
}
fn compressed_public(encoded: &[u8], width: usize) -> Vec<u8> {
    let x_end = width.checked_add(1).unwrap();
    assert_eq!(encoded.first(), Some(&4));
    assert_eq!(
        encoded.len(),
        width.checked_mul(2).unwrap().checked_add(1).unwrap()
    );
    let mut compressed = vec![2 | (encoded.last().unwrap() & 1)];
    compressed.extend_from_slice(&encoded[1..x_end]);
    compressed
}

fn vectors() -> Vec<Value> {
    let mut vectors: Value =
        serde_json::from_str(include_str!("data/ecdsa_explicit.json")).unwrap();
    vectors["vectors"]
        .as_array_mut()
        .unwrap()
        .drain(..)
        .filter(|v| portable(curve(&v["curve"])) || cfg!(feature = "brainpool"))
        .collect()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_enabled_curve_and_hash_executes_independent_known_answers() {
    let vectors = vectors();
    assert_eq!(
        vectors.len(),
        if cfg!(feature = "brainpool") { 7 } else { 3 }
    );
    for v in vectors {
        let curve = curve(&v["curve"]);
        let key = EcdsaKey::import(curve, &bytes(&v["scalar"])).unwrap();
        assert_eq!(key.public_key(), bytes(&v["public"]));
        assert_eq!(key.curve(), curve);
        validate_public_key(curve, key.public_key()).unwrap();
        let width = bytes(&v["scalar"]).len();
        let compressed = compressed_public(key.public_key(), width);
        validate_public_key(curve, &compressed).unwrap();
        let compressed_peer = compressed_public(&bytes(&v["peer_public"]), width);
        assert_eq!(
            key.agree(&compressed_peer).unwrap().expose_secret(),
            bytes(&v["shared"])
        );
        assert_eq!(
            key.agree(&bytes(&v["peer_public"]))
                .unwrap()
                .expose_secret(),
            bytes(&v["shared"])
        );
        for signature in v["signatures"].as_array().unwrap() {
            let hash = hash(&signature["hash"]);
            let message = bytes(&v["message"]);
            let digest = bytes(&signature["digest"]);
            let raw = bytes(&signature["raw"]);
            let input = EcdsaInput::Message {
                hash,
                bytes: &message,
            };
            verify(
                curve,
                key.public_key(),
                input,
                &raw,
                EcdsaEncoding::FixedWidth,
            )
            .unwrap();
            verify(curve, &compressed, input, &raw, EcdsaEncoding::FixedWidth).unwrap();
            assert_eq!(
                verify(
                    curve,
                    &bytes(&v["peer_public"]),
                    input,
                    &raw,
                    EcdsaEncoding::FixedWidth
                ),
                Err(EcdsaError::InvalidSignature)
            );
            verify(
                curve,
                key.public_key(),
                EcdsaInput::Prehash {
                    hash,
                    bytes: &digest,
                },
                &raw,
                EcdsaEncoding::FixedWidth,
            )
            .unwrap();
            verify(
                curve,
                key.public_key(),
                input,
                &bytes(&signature["high_s_raw"]),
                EcdsaEncoding::FixedWidth,
            )
            .unwrap();
            let high_s = bytes(&signature["high_s_raw"]);
            let high_s_der = fixed_to_der(curve, &high_s).unwrap();
            assert_eq!(der_to_fixed(curve, &high_s_der).unwrap(), high_s);
            verify(
                curve,
                key.public_key(),
                input,
                &high_s_der,
                EcdsaEncoding::Der,
            )
            .unwrap();
            let signed = key.sign(input, EcdsaEncoding::FixedWidth).unwrap();
            if portable(curve)
                || cfg!(all(
                    feature = "brainpool",
                    not(feature = "brainpool-openssl")
                ))
                || cfg!(all(feature = "brainpool", target_arch = "wasm32"))
            {
                // The portable backend uses deterministic RFC 6979 signing;
                // these expected bytes were calculated independently.
                assert_eq!(signed, raw, "curve/hash {:?}/{:?}", curve, hash);
            }
            verify(
                curve,
                key.public_key(),
                input,
                &signed,
                EcdsaEncoding::FixedWidth,
            )
            .unwrap();
            let der = fixed_to_der(curve, &raw).unwrap();
            assert_eq!(der_to_fixed(curve, &der).unwrap(), raw);
            verify(curve, key.public_key(), input, &der, EcdsaEncoding::Der).unwrap();
            let mut changed = message.clone();
            changed[0] ^= 1;
            assert_eq!(
                verify(
                    curve,
                    key.public_key(),
                    EcdsaInput::Message {
                        hash,
                        bytes: &changed
                    },
                    &raw,
                    EcdsaEncoding::FixedWidth
                ),
                Err(EcdsaError::InvalidSignature)
            );
            assert_eq!(
                verify(
                    curve,
                    key.public_key(),
                    EcdsaInput::Message {
                        hash,
                        bytes: &digest
                    },
                    &raw,
                    EcdsaEncoding::FixedWidth
                ),
                Err(EcdsaError::InvalidSignature)
            );
            assert_eq!(
                verify(curve, key.public_key(), input, &raw, EcdsaEncoding::Der),
                Err(EcdsaError::InvalidSignature)
            );
            assert_eq!(
                verify(
                    curve,
                    key.public_key(),
                    input,
                    &der,
                    EcdsaEncoding::FixedWidth
                ),
                Err(EcdsaError::InvalidSignature)
            );
            let mut trailing = der.clone();
            trailing.push(0);
            assert_eq!(
                der_to_fixed(curve, &trailing),
                Err(EcdsaError::InvalidSignature)
            );
            for prefix_length in 0..der.len() {
                assert_eq!(
                    der_to_fixed(curve, &der[..prefix_length]),
                    Err(EcdsaError::InvalidSignature)
                );
            }
            assert_eq!(
                der_to_fixed(curve, &[0x30; 1024]),
                Err(EcdsaError::InvalidSignature)
            );
        }
    }
}

struct PartialEntropyFailure;
impl reallyme_crypto::key_random::KeyRng for PartialEntropyFailure {
    fn fill(
        &mut self,
        destination: &mut [u8],
    ) -> Result<(), reallyme_crypto::key_random::KeyRandomError> {
        destination.fill(0xa5);
        Err(reallyme_crypto::key_random::KeyRandomError::Unavailable)
    }
}
struct ZeroEntropy;
impl reallyme_crypto::key_random::KeyRng for ZeroEntropy {
    fn fill(
        &mut self,
        destination: &mut [u8],
    ) -> Result<(), reallyme_crypto::key_random::KeyRandomError> {
        destination.fill(0);
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn entropy_failure_and_exhausted_rejection_sampling_return_typed_errors() {
    for vector in vectors() {
        let curve = curve(&vector["curve"]);
        assert!(matches!(
            EcdsaKey::generate_with_rng(curve, &mut PartialEntropyFailure),
            Err(EcdsaError::RandomnessUnavailable)
        ));
        assert!(matches!(
            EcdsaKey::generate_with_rng(curve, &mut ZeroEntropy),
            Err(EcdsaError::RandomnessUnavailable)
        ));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn certificate_and_crl_verification_uses_exact_tbs_spans_for_every_curve_and_hash() {
    let fixture: Value =
        serde_json::from_str(include_str!("data/certificate_crl_signatures.json")).unwrap();
    let mut executed = 0;
    for v in fixture["vectors"].as_array().unwrap() {
        let curve = curve(&v["curve"]);
        if !portable(curve) && !cfg!(feature = "brainpool") {
            continue;
        }
        let hash = hash(&v["hash"]);
        let tbs = bytes(&v["tbs"]);
        let whole = bytes(&v["der"]);
        let public = bytes(&v["public"]);
        let signature = bytes(&v["signature_der"]);
        let input = EcdsaInput::Message { hash, bytes: &tbs };
        verify(curve, &public, input, &signature, EcdsaEncoding::Der).unwrap();
        let raw = der_to_fixed(curve, &signature).unwrap();
        verify(curve, &public, input, &raw, EcdsaEncoding::FixedWidth).unwrap();
        assert_eq!(
            verify(
                curve,
                &public,
                EcdsaInput::Message {
                    hash,
                    bytes: &whole
                },
                &signature,
                EcdsaEncoding::Der
            ),
            Err(EcdsaError::InvalidSignature)
        );
        for position in [0, tbs.len() / 2, tbs.len() - 1] {
            let mut changed = tbs.clone();
            changed[position] ^= 1;
            assert_eq!(
                verify(
                    curve,
                    &public,
                    EcdsaInput::Message {
                        hash,
                        bytes: &changed
                    },
                    &signature,
                    EcdsaEncoding::Der
                ),
                Err(EcdsaError::InvalidSignature)
            );
        }
        executed += 1;
    }
    assert_eq!(executed, if cfg!(feature = "brainpool") { 42 } else { 18 });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_curve_rejects_invalid_scalars_points_encodings_and_lengths() {
    for v in vectors() {
        let curve = curve(&v["curve"]);
        let width = bytes(&v["scalar"]).len();
        let key = EcdsaKey::import(curve, &bytes(&v["scalar"])).unwrap();
        for scalar in [
            vec![],
            vec![0; width],
            vec![1; width - 1],
            vec![1; width + 1],
            bytes(&v["order"]),
        ] {
            assert!(matches!(
                EcdsaKey::import(curve, &scalar),
                Err(EcdsaError::InvalidPrivateKey)
            ));
        }
        for public in [
            vec![],
            vec![0],
            vec![4; 2 * width + 1],
            vec![6; 2 * width + 1],
            vec![2; width],
        ] {
            assert_eq!(
                validate_public_key(curve, &public),
                Err(EcdsaError::InvalidPublicKey)
            );
            assert!(matches!(
                key.agree(&public),
                Err(EcdsaError::InvalidPublicKey)
            ));
        }
        for raw in [vec![], vec![0; 2 * width], vec![1; 2 * width - 1]] {
            assert_eq!(fixed_to_der(curve, &raw), Err(EcdsaError::InvalidSignature));
        }
        let mut out_of_range = bytes(&v["order"]);
        out_of_range.extend(vec![1; width]);
        assert_eq!(
            fixed_to_der(curve, &out_of_range),
            Err(EcdsaError::InvalidSignature)
        );
        assert!(matches!(
            key.sign(
                EcdsaInput::Prehash {
                    hash: EcdsaHash::Sha256,
                    bytes: &[0; 31]
                },
                EcdsaEncoding::Der
            ),
            Err(EcdsaError::InvalidPrehashLength)
        ));
        let generated = EcdsaKey::generate(curve).unwrap();
        validate_public_key(curve, generated.public_key()).unwrap();
        assert_eq!(generated.public_key().len(), 2 * width + 1);
        // Leading zeros and the sign-padding octet survive format conversion,
        // including the 66-byte P-521 and 40-byte Brainpool scalar cases.
        let mut padded = vec![0; 2 * width];
        padded[width - 1] = 0x80;
        padded[2 * width - 1] = 1;
        assert_eq!(
            der_to_fixed(curve, &fixed_to_der(curve, &padded).unwrap()).unwrap(),
            padded
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn strict_der_syntax_and_curve_scalar_validation_share_one_contract() {
    use der_core::Decode;

    // A sibling consumer enables BER, but the shared codec signature parser
    // must still enforce DER independently of dependency feature unification.
    // This entry point exists only when the unified BER feature is enabled.
    assert_eq!(u8::from_ber(&[0x02, 0x01, 0x01]).unwrap(), 1);
    // Valid DER zero is still an invalid ECDSA scalar. Other cases exercise
    // BER forms, nonminimal lengths/signs, constructed INTEGERs and extra data.
    let malformed = [
        "3006020100020101",
        "3006020101020100",
        "30060201ff020101",
        "300702020001020101",
        "300702020000020101",
        "30800201010201010000",
        "308106020101020101",
        "300702810101020101",
        "3009020101020101020101",
        "3088ffffffffffffffff",
        "3006220101020101",
        "30050200020101",
        "3003020101",
        "300602010102010100",
    ];
    let minimal = hex::decode("3006020101020101").unwrap();
    for vector in vectors() {
        let curve = curve(&vector["curve"]);
        let public = bytes(&vector["public"]);
        let width = bytes(&vector["scalar"]).len();
        let zero_scalar = hex::decode("3006020100020101").unwrap();
        assert_eq!(
            verify(
                curve,
                &public,
                EcdsaInput::Prehash {
                    hash: EcdsaHash::Sha256,
                    bytes: &[0; 31]
                },
                &zero_scalar,
                EcdsaEncoding::Der,
            ),
            Err(EcdsaError::InvalidPrehashLength)
        );
        assert_eq!(
            verify(
                curve,
                &[],
                EcdsaInput::Message {
                    hash: EcdsaHash::Sha256,
                    bytes: b"invalid key"
                },
                &zero_scalar,
                EcdsaEncoding::Der,
            ),
            Err(EcdsaError::InvalidPublicKey)
        );
        let mut fixed = vec![0; 2 * width];
        fixed[width - 1] = 1;
        fixed[2 * width - 1] = 1;
        assert_eq!(der_to_fixed(curve, &minimal).unwrap(), fixed);
        for encoded in malformed {
            let der = hex::decode(encoded).unwrap();
            assert_eq!(der_to_fixed(curve, &der), Err(EcdsaError::InvalidSignature));
            assert_eq!(
                verify(
                    curve,
                    &public,
                    EcdsaInput::Message {
                        hash: EcdsaHash::Sha256,
                        bytes: b"strict DER boundary",
                    },
                    &der,
                    EcdsaEncoding::Der,
                ),
                Err(EcdsaError::InvalidSignature)
            );
        }
    }
}

// Build public test inputs without applying crypto's scalar-range checks.
// In particular, q is valid ASN.1 but must never become a valid ECDSA scalar.
fn der_pair_for_scalar_boundary(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for magnitude in [first, second] {
        let start = magnitude.iter().position(|byte| *byte != 0).unwrap();
        let magnitude = &magnitude[start..];
        let padding = usize::from(magnitude[0] & 0x80 != 0);
        body.push(0x02);
        body.push(u8::try_from(magnitude.len().checked_add(padding).unwrap()).unwrap());
        if padding != 0 {
            body.push(0);
        }
        body.extend_from_slice(magnitude);
    }
    let mut encoded = vec![0x30];
    if body.len() >= 128 {
        encoded.push(0x81);
    }
    encoded.push(u8::try_from(body.len()).unwrap());
    encoded.extend_from_slice(&body);
    encoded
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn der_scalar_orders_are_rejected_without_rejecting_their_predecessors() {
    for vector in vectors() {
        let curve = curve(&vector["curve"]);
        let order = bytes(&vector["order"]);
        let mut previous = order.clone();
        for byte in previous.iter_mut().rev() {
            let (value, borrow) = byte.overflowing_sub(1);
            *byte = value;
            if !borrow {
                break;
            }
        }
        let accepted = der_pair_for_scalar_boundary(&previous, &previous);
        let mut expected = previous.clone();
        expected.extend_from_slice(&previous);
        assert_eq!(der_to_fixed(curve, &accepted).unwrap(), expected);
        assert_eq!(fixed_to_der(curve, &expected).unwrap(), accepted);
        for rejected in [
            der_pair_for_scalar_boundary(&order, &[1]),
            der_pair_for_scalar_boundary(&[1], &order),
        ] {
            assert_eq!(
                der_to_fixed(curve, &rejected),
                Err(EcdsaError::InvalidSignature)
            );
            assert_eq!(
                verify(
                    curve,
                    &bytes(&vector["public"]),
                    EcdsaInput::Message {
                        hash: EcdsaHash::Sha256,
                        bytes: b"scalar boundary"
                    },
                    &rejected,
                    EcdsaEncoding::Der,
                ),
                Err(EcdsaError::InvalidSignature)
            );
        }
    }
}

struct NonExporting(EcdsaKey);
impl OpaqueEcdsaSigner for NonExporting {
    fn curve(&self) -> EcdsaCurve {
        self.0.curve()
    }
    fn public_key(&self) -> &[u8] {
        self.0.public_key()
    }
    fn sign_prehash(
        &self,
        hash: EcdsaHash,
        bytes: &[u8],
        encoding: EcdsaEncoding,
    ) -> Result<Vec<u8>, EcdsaError> {
        self.0.sign(EcdsaInput::Prehash { hash, bytes }, encoding)
    }
}
struct Unavailable(NonExporting);
impl OpaqueEcdsaSigner for Unavailable {
    fn curve(&self) -> EcdsaCurve {
        self.0.curve()
    }
    fn public_key(&self) -> &[u8] {
        self.0.public_key()
    }
    fn sign_prehash(
        &self,
        _: EcdsaHash,
        _: &[u8],
        _: EcdsaEncoding,
    ) -> Result<Vec<u8>, EcdsaError> {
        Err(EcdsaError::ProviderFailed)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn opaque_signing_executes_without_private_export_and_preserves_typed_failure() {
    for v in vectors() {
        let key = NonExporting(EcdsaKey::import(curve(&v["curve"]), &bytes(&v["scalar"])).unwrap());
        let message = b"exact opaque signing input";
        let input = EcdsaInput::Message {
            hash: EcdsaHash::Sha384,
            bytes: message,
        };
        for encoding in [EcdsaEncoding::Der, EcdsaEncoding::FixedWidth] {
            let signature = sign_with_provider(&key, input, encoding).unwrap();
            verify(key.curve(), key.public_key(), input, &signature, encoding).unwrap();
        }
        assert_eq!(
            sign_with_provider(&Unavailable(key), input, EcdsaEncoding::Der),
            Err(EcdsaError::ProviderFailed)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn clearing_owners_fail_closed_after_explicit_destruction() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(std::mem::needs_drop::<T>());
    }
    clearing::<EcdsaKey>();
    clearing::<secrecy::SecretSlice<u8>>();
    let mut key = EcdsaKey::generate(EcdsaCurve::P256).unwrap();
    key.zeroize();
    assert!(matches!(
        key.sign(
            EcdsaInput::Message {
                hash: EcdsaHash::Sha256,
                bytes: b"message"
            },
            EcdsaEncoding::Der
        ),
        Err(EcdsaError::InvalidPrivateKey)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg(not(feature = "brainpool"))]
fn absent_brainpool_provider_reports_unsupported_for_every_operation() {
    for curve in [
        EcdsaCurve::BrainpoolP256r1,
        EcdsaCurve::BrainpoolP320r1,
        EcdsaCurve::BrainpoolP384r1,
        EcdsaCurve::BrainpoolP512r1,
    ] {
        assert!(matches!(
            EcdsaKey::generate(curve),
            Err(EcdsaError::UnsupportedCurve)
        ));
        assert!(matches!(
            EcdsaKey::import(curve, &[1; 32]),
            Err(EcdsaError::UnsupportedCurve)
        ));
        assert_eq!(
            validate_public_key(curve, &[4; 65]),
            Err(EcdsaError::UnsupportedCurve)
        );
        assert_eq!(der_to_fixed(curve, &[]), Err(EcdsaError::UnsupportedCurve));
        assert_eq!(fixed_to_der(curve, &[]), Err(EcdsaError::UnsupportedCurve));
    }
}
