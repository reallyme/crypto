// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HPKE RFC 9180 known-answer test adapter.
//!
//! Executes the base-mode (`mode = 0`) vectors from the CFRG HPKE draft's
//! `test-vectors.json` against the public single-shot API for the suites
//! ReallyMe exposes: derandomized seal (seeded with the vector's `ikmE`) must
//! reproduce the encapsulated key and first ciphertext, and open must recover
//! the plaintext. The context-binding test uses independent Base and PSK
//! records from the same corpus and substitutes one input at a time. The
//! stateful PSK test stays on one context per direction through all 257
//! published records per suite while checking retries and record ordering.
//! A second stateful test checks isolation between two encapsulations with
//! the same PSK and record inputs.

use crypto_hpke::{
    open_base, open_psk, receiver_export, seal_base_derand, sender_export_derand,
    setup_receiver_psk, setup_sender_psk_derand, HpkeAeadId, HpkeDerandPskSenderSetupRequest,
    HpkeDerandSealRequest, HpkeDerandSenderExportRequest, HpkeError, HpkeKdfId, HpkeKemId,
    HpkeOpenOutput, HpkeOpenRequest, HpkePskIdRef, HpkePskOpenRequest, HpkePskReceiverSetupRequest,
    HpkePskRef, HpkePskSenderSetupOutput, HpkeReceiverContext, HpkeReceiverExportRequest,
    HpkeSuite, HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM, HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
    HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM, HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
};
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_json, AuditError};
use serde::Deserialize;
use zeroize::Zeroizing;

const BASE_MODE: u32 = 0;
const PSK_MODE: u32 = 1;
const RFC_RECORD_COUNT: usize = 257;
const CORPUS: &str = "hpke/rfc9180_test_vectors.json";
const AUDITED_SUITES: [HpkeSuite; 5] = [
    HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM,
    HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
    HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
];

#[derive(Deserialize)]
struct HpkeVector {
    mode: u32,
    kem_id: u32,
    kdf_id: u32,
    aead_id: u32,
    info: String,
    #[serde(rename = "pkRm")]
    pk_rm: String,
    #[serde(rename = "skRm")]
    sk_rm: String,
    #[serde(rename = "ikmE")]
    ikm_e: String,
    enc: String,
    encryptions: Vec<HpkeEncryption>,
    exports: Vec<HpkeExport>,
    psk: Option<String>,
    psk_id: Option<String>,
}

#[derive(Deserialize)]
struct HpkeExport {
    exporter_context: String,
    #[serde(rename = "L")]
    length: usize,
    exported_value: String,
}

#[derive(Deserialize)]
struct HpkeEncryption {
    aad: String,
    ct: String,
    pt: String,
}

#[test]
#[ignore = "vendored RFC 9180 corpus; run via the external-vectors audit workflow after vendoring"]
fn rfc9180_hpke_base_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let vectors: Vec<HpkeVector> = load_json(CORPUS)?;
    let mut executed = 0usize;

    for vector in &vectors {
        if vector.mode != BASE_MODE {
            continue;
        }
        let suite = match AUDITED_SUITES
            .into_iter()
            .find(|suite| matches_suite(vector, *suite))
        {
            Some(suite) => suite,
            None => continue,
        };
        // First encryption uses sequence number 0, which the single-shot API
        // produces; later sequence numbers need an evolving context.
        let encryption = match vector.encryptions.first() {
            Some(encryption) => encryption,
            None => continue,
        };

        let recipient_public_key = hex_bytes(&vector.pk_rm)?;
        let recipient_private_key = Zeroizing::new(hex_bytes(&vector.sk_rm)?);
        let encapsulation_randomness = Zeroizing::new(hex_bytes(&vector.ikm_e)?);
        let info = hex_bytes(&vector.info)?;
        let aad = hex_bytes(&encryption.aad)?;
        let plaintext = Zeroizing::new(hex_bytes(&encryption.pt)?);
        let expected_enc = hex_bytes(&vector.enc)?;
        let expected_ct = hex_bytes(&encryption.ct)?;

        // Derandomized seal reproduces the encapsulated key and ciphertext.
        let sealed = seal_base_derand(&HpkeDerandSealRequest {
            suite,
            recipient_public_key: &recipient_public_key,
            encapsulation_randomness: &encapsulation_randomness,
            info: &info,
            aad: &aad,
            plaintext: &plaintext,
        })
        .map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(&sealed.encapsulated_key, &expected_enc)?;
        assert_bytes_eq(&sealed.ciphertext, &expected_ct)?;

        // Open recovers the plaintext.
        let opened = open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: &expected_enc,
            recipient_private_key: &recipient_private_key,
            info: &info,
            aad: &aad,
            ciphertext: &expected_ct,
        })
        .map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(opened.plaintext.as_slice(), &plaintext)?;

        executed = executed
            .checked_add(1)
            .ok_or(AuditError::NoExecutableVectors)?;
    }

    if executed == 0 {
        return Err(AuditError::NoExecutableVectors);
    }
    Ok(())
}

fn matches_suite(vector: &HpkeVector, suite: HpkeSuite) -> bool {
    vector.kem_id == u32::from(suite.kem_id())
        && vector.kdf_id == u32::from(suite.kdf_id())
        && vector.aead_id == u32::from(suite.aead_id())
}

#[test]
#[ignore = "vendored RFC 9180 corpus; run via the external-vectors audit workflow after vendoring"]
fn rfc9180_hpke_public_psk_contexts_retry_each_record() -> Result<(), AuditError> {
    let vectors: Vec<HpkeVector> = load_json(CORPUS)?;
    for suite in AUDITED_SUITES {
        let vector = find_vector(&vectors, PSK_MODE, suite)?;
        assert_eq!(vector.encryptions.len(), RFC_RECORD_COUNT);
        let randomness = Zeroizing::new(hex_bytes(&vector.ikm_e)?);
        let (mut sender, mut receiver) = setup_public_psk_contexts(vector, suite, &randomness)?;
        assert_bytes_eq(&sender.encapsulated_key, &hex_bytes(&vector.enc)?)?;

        for (seq, record) in vector.encryptions.iter().enumerate() {
            let aad = hex_bytes(&record.aad)?;
            let ct = hex_bytes(&record.ct)?;
            let pt = Zeroizing::new(hex_bytes(&record.pt)?);
            let sealed = sender
                .context
                .seal(&aad, &pt)
                .map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(&sealed, &ct)?;

            // Keep each misplaced record's published AAD and ciphertext
            // intact. Replay the previous record and deliver the next two
            // records early. All three records authenticate in their
            // proper positions on this same receiver.
            let misplaced = [seq.checked_sub(1), seq.checked_add(2), seq.checked_add(1)];
            for offered in misplaced.into_iter().flatten() {
                let Some(other) = vector.encryptions.get(offered) else {
                    continue;
                };
                let other_aad = hex_bytes(&other.aad)?;
                let other_ct = hex_bytes(&other.ct)?;
                assert_eq!(
                    receiver.open(&other_aad, &other_ct).err(),
                    Some(HpkeError::PRIMITIVE_AUTHENTICATION_FAILED),
                    "suite {suite:?}, sequence {seq}, offered sequence {offered}"
                );
            }

            let mut bad_tag = ct.clone();
            *bad_tag.last_mut().ok_or(AuditError::Shape)? ^= 1;
            // A rejected record must let the caller retry the same sequence
            // through the public context, including the nonce carry at 256.
            assert_eq!(
                receiver.open(&aad, &bad_tag).err(),
                Some(HpkeError::PRIMITIVE_AUTHENTICATION_FAILED),
                "suite {suite:?}, sequence {seq}"
            );
            let opened = receiver.open(&aad, &ct).map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(opened.plaintext.as_slice(), &pt)?;
        }
    }
    Ok(())
}

#[test]
#[ignore = "vendored RFC 9180 corpus; run via the external-vectors audit workflow after vendoring"]
fn rfc9180_hpke_public_psk_contexts_reject_each_others_records() -> Result<(), AuditError> {
    let vectors: Vec<HpkeVector> = load_json(CORPUS)?;
    for suite in AUDITED_SUITES {
        let vector = find_vector(&vectors, PSK_MODE, suite)?;
        let alternate = find_vector(&vectors, BASE_MODE, suite)?;
        assert_eq!(vector.encryptions.len(), RFC_RECORD_COUNT);
        let randomness = Zeroizing::new(hex_bytes(&vector.ikm_e)?);
        let alternate_randomness = Zeroizing::new(hex_bytes(&alternate.ikm_e)?);
        if *randomness == *alternate_randomness {
            return Err(AuditError::Shape);
        }
        // Borrow only the alternate row's encapsulation randomness. Both
        // setups use the same PSK row for the recipient, PSK, ID, and info.
        let (mut sender, mut receiver) = setup_public_psk_contexts(vector, suite, &randomness)?;
        let (mut alternate_sender, mut alternate_receiver) =
            setup_public_psk_contexts(vector, suite, &alternate_randomness)?;
        assert_bytes_eq(&sender.encapsulated_key, &hex_bytes(&vector.enc)?)?;
        // These DHKEM encapsulations encode the ephemeral public key.
        assert_bytes_eq(
            &alternate_sender.encapsulated_key,
            &hex_bytes(&alternate.enc)?,
        )?;
        assert!(
            sender.encapsulated_key != alternate_sender.encapsulated_key,
            "distinct encapsulations for suite {suite:?}"
        );

        for (seq, record) in vector.encryptions.iter().enumerate() {
            let aad = hex_bytes(&record.aad)?;
            let plaintext = Zeroizing::new(hex_bytes(&record.pt)?);
            let ciphertext = sender
                .context
                .seal(&aad, &plaintext)
                .map_err(|_| AuditError::Mismatch)?;
            let alternate_ciphertext = alternate_sender
                .context
                .seal(&aad, &plaintext)
                .map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(&ciphertext, &hex_bytes(&record.ct)?)?;

            // Send each intact record to the other receiver first. An
            // authentic open on each receiver then checks that rejection
            // left both contexts at the same sequence.
            for (receiver, foreign, own) in [
                (&mut receiver, &alternate_ciphertext, &ciphertext),
                (&mut alternate_receiver, &ciphertext, &alternate_ciphertext),
            ] {
                assert_eq!(
                    receiver.open(&aad, foreign).err(),
                    Some(HpkeError::PRIMITIVE_AUTHENTICATION_FAILED),
                    "cross-context open for suite {suite:?}, sequence {seq}"
                );
                let opened = receiver.open(&aad, own).map_err(|_| AuditError::Mismatch)?;
                assert_bytes_eq(opened.plaintext.as_slice(), &plaintext)?;
            }
        }
    }
    Ok(())
}

fn setup_public_psk_contexts(
    vector: &HpkeVector,
    suite: HpkeSuite,
    randomness: &[u8],
) -> Result<(HpkePskSenderSetupOutput, HpkeReceiverContext), AuditError> {
    let public_key = hex_bytes(&vector.pk_rm)?;
    let private_key = Zeroizing::new(hex_bytes(&vector.sk_rm)?);
    let info = hex_bytes(&vector.info)?;
    let psk_bytes = Zeroizing::new(hex_bytes(vector.psk.as_deref().ok_or(AuditError::Shape)?)?);
    let psk_id_bytes = hex_bytes(vector.psk_id.as_deref().ok_or(AuditError::Shape)?)?;
    let sender = setup_sender_psk_derand(&HpkeDerandPskSenderSetupRequest {
        suite,
        recipient_public_key: &public_key,
        encapsulation_randomness: randomness,
        info: &info,
        psk: HpkePskRef::new(&psk_bytes).map_err(|_| AuditError::Shape)?,
        psk_id: HpkePskIdRef::new(&psk_id_bytes).map_err(|_| AuditError::Shape)?,
    })
    .map_err(|_| AuditError::Mismatch)?;
    let receiver = setup_receiver_psk(&HpkePskReceiverSetupRequest {
        suite,
        encapsulated_key: &sender.encapsulated_key,
        recipient_private_key: &private_key,
        info: &info,
        psk: HpkePskRef::new(&psk_bytes).map_err(|_| AuditError::Shape)?,
        psk_id: HpkePskIdRef::new(&psk_id_bytes).map_err(|_| AuditError::Shape)?,
    })
    .map_err(|_| AuditError::Mismatch)?;
    Ok((sender, receiver))
}

#[test]
#[ignore = "vendored RFC 9180 corpus; run via the external-vectors audit workflow after vendoring"]
fn rfc9180_hpke_open_binds_context_in_base_and_psk_modes() -> Result<(), AuditError> {
    let vectors: Vec<HpkeVector> = load_json(CORPUS)?;
    for suite in AUDITED_SUITES {
        let base = find_vector(&vectors, BASE_MODE, suite)?;
        let psk = find_vector(&vectors, PSK_MODE, suite)?;
        // Each alternate key is used successfully by the other record under
        // the same KEM and suite, so an invalid key cannot satisfy a negative test.
        if base.pk_rm == psk.pk_rm {
            return Err(AuditError::Shape);
        }
        check_context(base, psk, suite)?;
        check_context(psk, base, suite)?;
    }
    Ok(())
}

fn find_vector(
    vectors: &[HpkeVector],
    mode: u32,
    suite: HpkeSuite,
) -> Result<&HpkeVector, AuditError> {
    vectors
        .iter()
        .find(|vector| vector.mode == mode && matches_suite(vector, suite))
        .ok_or(AuditError::NoExecutableVectors)
}

fn check_context(
    vector: &HpkeVector,
    other_recipient: &HpkeVector,
    suite: HpkeSuite,
) -> Result<(), AuditError> {
    let [first, second, ..] = vector.encryptions.as_slice() else {
        return Err(AuditError::Shape);
    };
    let enc = hex_bytes(&vector.enc)?;
    let private_key = Zeroizing::new(hex_bytes(&vector.sk_rm)?);
    let wrong_private_key = Zeroizing::new(hex_bytes(&other_recipient.sk_rm)?);
    let info = hex_bytes(&vector.info)?;
    let aad = hex_bytes(&first.aad)?;
    let ciphertext = hex_bytes(&first.ct)?;
    let plaintext = Zeroizing::new(hex_bytes(&first.pt)?);
    let psk = match (vector.mode, &vector.psk, &vector.psk_id) {
        (BASE_MODE, None, None) => None,
        (PSK_MODE, Some(psk), Some(id)) => Some((Zeroizing::new(hex_bytes(psk)?), hex_bytes(id)?)),
        _ => return Err(AuditError::Shape),
    };
    let psk = psk
        .as_ref()
        .map(|(key, id)| (key.as_slice(), id.as_slice()));
    let baseline = HpkeOpenRequest {
        suite,
        encapsulated_key: &enc,
        recipient_private_key: &private_key,
        info: &info,
        aad: &aad,
        ciphertext: &ciphertext,
    };
    let opened = open_vector(&baseline, psk).map_err(|_| AuditError::Mismatch)?;
    assert_bytes_eq(opened.plaintext.as_slice(), &plaintext)?;

    // Hold the KEM fixed so the alternate suite can parse the original record.
    let other_kdf = HpkeKdfId::HkdfSha384;
    assert_ne!(suite.kdf, other_kdf);
    let other_aead = if suite.aead == HpkeAeadId::Aes128Gcm {
        HpkeAeadId::Aes256Gcm
    } else {
        HpkeAeadId::Aes128Gcm
    };
    let mut wrong_info = info.clone();
    *wrong_info.first_mut().ok_or(AuditError::Shape)? ^= 1;
    // Use the next upstream AAD value with the sequence-zero record.
    let wrong_aad = hex_bytes(&second.aad)?;
    if aad == wrong_aad || *private_key == *wrong_private_key {
        return Err(AuditError::Shape);
    }
    for (name, changed) in [
        (
            "suite KDF",
            HpkeOpenRequest {
                suite: HpkeSuite {
                    kdf: other_kdf,
                    ..suite
                },
                ..baseline
            },
        ),
        (
            "suite AEAD",
            HpkeOpenRequest {
                suite: HpkeSuite {
                    aead: other_aead,
                    ..suite
                },
                ..baseline
            },
        ),
        (
            "recipient key",
            HpkeOpenRequest {
                recipient_private_key: &wrong_private_key,
                ..baseline
            },
        ),
        (
            "info",
            HpkeOpenRequest {
                info: &wrong_info,
                ..baseline
            },
        ),
        (
            "AAD",
            HpkeOpenRequest {
                aad: &wrong_aad,
                ..baseline
            },
        ),
    ] {
        assert_eq!(
            open_vector(&changed, psk).err(),
            Some(HpkeError::PRIMITIVE_AUTHENTICATION_FAILED),
            "RFC 9180 mode {}, suite {:?}, changed {name}",
            vector.mode,
            suite,
        );
    }
    // Keep the PSK bytes and the encryption transcript fixed so this checks
    // that changing only the identifier invalidates the record.
    if let Some((key, id)) = psk {
        let mut wrong_id = id.to_vec();
        *wrong_id.first_mut().ok_or(AuditError::Shape)? ^= 1;
        assert_eq!(
            open_vector(&baseline, Some((key, &wrong_id))).err(),
            Some(HpkeError::PRIMITIVE_AUTHENTICATION_FAILED),
            "RFC 9180 PSK suite {suite:?}, changed PSK identifier",
        );
    }
    Ok(())
}

fn open_vector(
    request: &HpkeOpenRequest<'_>,
    psk: Option<(&[u8], &[u8])>,
) -> Result<HpkeOpenOutput, HpkeError> {
    match psk {
        None => open_base(request),
        Some((psk, psk_id)) => open_psk(&HpkePskOpenRequest {
            suite: request.suite,
            encapsulated_key: request.encapsulated_key,
            recipient_private_key: request.recipient_private_key,
            info: request.info,
            aad: request.aad,
            ciphertext: request.ciphertext,
            psk,
            psk_id,
        }),
    }
}

#[test]
#[ignore = "vendored RFC 9180 corpus; run via the external-vectors audit workflow after vendoring"]
fn rfc9180_hpke_public_base_exporters_match() -> Result<(), AuditError> {
    let vectors: Vec<HpkeVector> = load_json(CORPUS)?;
    let export_only = HpkeSuite::new(
        HpkeKemId::DhKemX25519HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::ExportOnly,
    );
    for suite in AUDITED_SUITES.into_iter().chain([export_only]) {
        let vector = find_vector(&vectors, BASE_MODE, suite)?;
        assert_eq!(vector.exports.len(), 3);
        let recipient_public_key = hex_bytes(&vector.pk_rm)?;
        let recipient_private_key = Zeroizing::new(hex_bytes(&vector.sk_rm)?);
        let encapsulation_randomness = Zeroizing::new(hex_bytes(&vector.ikm_e)?);
        let enc = hex_bytes(&vector.enc)?;
        let info = hex_bytes(&vector.info)?;
        for export in &vector.exports {
            let context = hex_bytes(&export.exporter_context)?;
            let expected = Zeroizing::new(hex_bytes(&export.exported_value)?);
            let sender = sender_export_derand(&HpkeDerandSenderExportRequest {
                suite,
                recipient_public_key: &recipient_public_key,
                encapsulation_randomness: &encapsulation_randomness,
                info: &info,
                exporter_context: &context,
                output_length: export.length,
            })
            .map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(&sender.encapsulated_key, &enc)?;
            assert_bytes_eq(sender.exporter_secret(), &expected)?;

            let request = HpkeReceiverExportRequest {
                suite,
                encapsulated_key: &enc,
                recipient_private_key: &recipient_private_key,
                info: &info,
                exporter_context: &context,
                output_length: export.length,
            };
            let receiver = receiver_export(&request).map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(receiver.as_slice(), &expected)?;

            // RFC 9180 includes L in LabeledExpand. A longer export with the
            // same context must derive new bytes instead of extending a prefix.
            let longer_length = export.length.checked_add(1).ok_or(AuditError::Shape)?;
            let longer = receiver_export(&HpkeReceiverExportRequest {
                output_length: longer_length,
                ..request
            })
            .map_err(|_| AuditError::Mismatch)?;
            assert_eq!(longer.as_slice().len(), longer_length);
            assert!(
                !longer.as_slice().starts_with(&expected),
                "export length binding"
            );
        }
    }
    Ok(())
}
