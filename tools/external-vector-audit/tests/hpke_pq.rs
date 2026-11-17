// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public HPKE checks against published Base vectors and the IETF reference PSK fixtures.

#![cfg(feature = "native")]

use crypto_hpke::{
    open_base, receiver_export, seal_base_derand, sender_export_derand, setup_receiver_psk,
    setup_sender_psk_derand, HpkeAeadId, HpkeDerandPskSenderSetupRequest, HpkeDerandSealRequest,
    HpkeDerandSenderExportRequest, HpkeError, HpkeKdfId, HpkeKemId, HpkeOpenRequest, HpkePskIdRef,
    HpkePskReceiverSetupRequest, HpkePskRef, HpkePskSenderSetupOutput, HpkeReceiverContext,
    HpkeReceiverExportRequest, HpkeSuite,
};
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_json, AuditError};
use serde::Deserialize;
use zeroize::Zeroizing;

const CORPUS: &str = "hpke/hpke_pq_draft05_test_vectors.json";
const PSK_CORPUS: &str = "hpke/hpke_pq_draft05_psk_test_vectors.json";
const BASE_MODE: u16 = 0;
const PSK_MODE: u16 = 1;
const PSK_VECTOR_COUNT: usize = 10;
const PSK_RECORD_COUNT: usize = 10;
const XWING_X25519_ENCAPSULATED_KEY_LEN: usize = 32;
const AUDITED_SUITES: [HpkeSuite; 5] = [
    HpkeSuite::new(
        HpkeKemId::MlKem512,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes128Gcm,
    ),
    HpkeSuite::new(
        HpkeKemId::MlKem768,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes128Gcm,
    ),
    HpkeSuite::new(
        HpkeKemId::MlKem1024,
        HpkeKdfId::HkdfSha384,
        HpkeAeadId::Aes256Gcm,
    ),
    HpkeSuite::new(
        HpkeKemId::XWing,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::ChaCha20Poly1305,
    ),
    HpkeSuite::new(
        HpkeKemId::XWing,
        HpkeKdfId::Shake256,
        HpkeAeadId::ChaCha20Poly1305,
    ),
];

#[derive(Deserialize)]
struct Vector {
    mode: u16,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    info: String,
    #[serde(rename = "pkRm")]
    public_key: String,
    #[serde(rename = "skRm")]
    private_key: String,
    #[serde(rename = "ikmE")]
    encapsulation_randomness: String,
    enc: String,
    encryptions: Vec<Encryption>,
    exports: Vec<Export>,
}

impl Vector {
    fn matches(&self, mode: u16, suite: HpkeSuite) -> bool {
        (self.mode, self.kem_id, self.kdf_id, self.aead_id)
            == (mode, suite.kem_id(), suite.kdf_id(), suite.aead_id())
    }
}

#[derive(Deserialize)]
struct PskVector {
    #[serde(flatten)]
    vector: Vector,
    psk: String,
    psk_id: String,
}

#[derive(Deserialize)]
struct Encryption {
    aad: String,
    ct: String,
    pt: String,
}

#[derive(Deserialize)]
struct Export {
    exporter_context: String,
    #[serde(rename = "L")]
    length: usize,
    exported_value: String,
}

#[test]
fn hpke_pq_vectors_match_and_reject_substituted_encapsulations() -> Result<(), AuditError> {
    let vectors: Vec<Vector> = load_json(CORPUS)?;
    for suite in AUDITED_SUITES {
        let mut selected = vectors
            .iter()
            .filter(|vector| vector.matches(BASE_MODE, suite));
        let vector = selected.next().ok_or(AuditError::NoExecutableVectors)?;
        if selected.next().is_some() {
            return Err(AuditError::Shape);
        }
        check_vector(vector, suite)?;
    }
    Ok(())
}

#[test]
fn hpke_pq_psk_contexts_reject_each_others_records() -> Result<(), AuditError> {
    let vectors: Vec<PskVector> = load_json(PSK_CORPUS)?;
    assert_eq!(vectors.len(), PSK_VECTOR_COUNT);
    for suite in AUDITED_SUITES {
        let [first, second] = psk_pair(&vectors, suite)?;
        check_psk_pair(suite, first, second)?;
    }
    Ok(())
}

#[test]
fn hpke_pq_psk_open_binds_identifier_and_info() -> Result<(), AuditError> {
    let vectors: Vec<PskVector> = load_json(PSK_CORPUS)?;
    assert_eq!(vectors.len(), PSK_VECTOR_COUNT);
    for suite in AUDITED_SUITES {
        for row in psk_pair(&vectors, suite)? {
            check_psk_transcript(suite, row)?;
        }
    }
    Ok(())
}

fn psk_pair(vectors: &[PskVector], suite: HpkeSuite) -> Result<[&PskVector; 2], AuditError> {
    let mut pair = vectors
        .iter()
        .filter(|row| row.vector.matches(PSK_MODE, suite));
    let first = pair.next().ok_or(AuditError::NoExecutableVectors)?;
    let second = pair.next().ok_or(AuditError::NoExecutableVectors)?;
    if pair.next().is_some() {
        return Err(AuditError::Shape);
    }
    Ok([first, second])
}

fn check_psk_transcript(suite: HpkeSuite, row: &PskVector) -> Result<(), AuditError> {
    // Each receiver starts at sequence zero. A receiver with a substituted
    // transcript cannot advance through the authentic stream to later records.
    let vector = &row.vector;
    let record = vector.encryptions.first().ok_or(AuditError::Shape)?;
    let enc = hex_bytes(&vector.enc)?;
    let private_key = Zeroizing::new(hex_bytes(&vector.private_key)?);
    let psk = Zeroizing::new(hex_bytes(&row.psk)?);
    let id = hex_bytes(&row.psk_id)?;
    let info = hex_bytes(&vector.info)?;
    let aad = hex_bytes(&record.aad)?;
    let ciphertext = hex_bytes(&record.ct)?;
    let expected = Zeroizing::new(hex_bytes(&record.pt)?);

    let receiver = |info, id| {
        setup_receiver_psk(&HpkePskReceiverSetupRequest {
            suite,
            encapsulated_key: &enc,
            recipient_private_key: &private_key,
            info,
            psk: HpkePskRef::new(&psk).map_err(|_| AuditError::Shape)?,
            psk_id: HpkePskIdRef::new(id).map_err(|_| AuditError::Shape)?,
        })
        .map_err(|_| AuditError::Mismatch)
    };
    let opened = receiver(info.as_slice(), id.as_slice())?
        .open(&aad, &ciphertext)
        .map_err(|_| AuditError::Mismatch)?;
    assert_bytes_eq(opened.plaintext.as_slice(), &expected)?;

    let mut wrong_id = id.clone();
    *wrong_id.first_mut().ok_or(AuditError::Shape)? ^= 1;
    let mut wrong_info = info.clone();
    *wrong_info.first_mut().ok_or(AuditError::Shape)? ^= 1;
    // Both substitutions must pass setup with the original PSK bytes.
    // The unchanged record is what detects the mismatch at open.
    for (name, info, id) in [
        ("PSK identifier", info.as_slice(), wrong_id.as_slice()),
        ("info", wrong_info.as_slice(), id.as_slice()),
    ] {
        assert_eq!(
            receiver(info, id)?.open(&aad, &ciphertext).err(),
            Some(HpkeError::PRIMITIVE_AUTHENTICATION_FAILED),
            "suite {suite:?}, changed {name}"
        );
    }
    Ok(())
}

fn check_psk_pair(
    suite: HpkeSuite,
    first: &PskVector,
    second: &PskVector,
) -> Result<(), AuditError> {
    let a = &first.vector;
    let b = &second.vector;
    if (
        a.public_key.as_str(),
        a.private_key.as_str(),
        a.info.as_str(),
        &first.psk,
        &first.psk_id,
    ) != (
        b.public_key.as_str(),
        b.private_key.as_str(),
        b.info.as_str(),
        &second.psk,
        &second.psk_id,
    ) || a.enc == b.enc
        || a.encapsulation_randomness == b.encapsulation_randomness
        || a.encryptions.len() != PSK_RECORD_COUNT
        || b.encryptions.len() != PSK_RECORD_COUNT
    {
        return Err(AuditError::Shape);
    }

    let (mut sender, mut receiver) = setup_psk_vector(suite, first)?;
    let (mut other_sender, mut other_receiver) = setup_psk_vector(suite, second)?;
    for (seq, (record, other_record)) in a.encryptions.iter().zip(&b.encryptions).enumerate() {
        if record.aad != other_record.aad || record.pt != other_record.pt {
            return Err(AuditError::Shape);
        }
        let aad = hex_bytes(&record.aad)?;
        let plaintext = Zeroizing::new(hex_bytes(&record.pt)?);
        let ct = sender
            .context
            .seal(&aad, &plaintext)
            .map_err(|_| AuditError::Mismatch)?;
        let other_ct = other_sender
            .context
            .seal(&aad, &plaintext)
            .map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(&ct, &hex_bytes(&record.ct)?)?;
        assert_bytes_eq(&other_ct, &hex_bytes(&other_record.ct)?)?;

        // Both records are independently verified at this sequence and
        // share the same AAD. Reject the other record before opening ours.
        for (receiver, foreign, own) in [
            (&mut receiver, &other_ct, &ct),
            (&mut other_receiver, &ct, &other_ct),
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
    Ok(())
}

fn setup_psk_vector(
    suite: HpkeSuite,
    row: &PskVector,
) -> Result<(HpkePskSenderSetupOutput, HpkeReceiverContext), AuditError> {
    let vector = &row.vector;
    let public_key = hex_bytes(&vector.public_key)?;
    let private_key = Zeroizing::new(hex_bytes(&vector.private_key)?);
    let randomness = Zeroizing::new(hex_bytes(&vector.encapsulation_randomness)?);
    let enc = hex_bytes(&vector.enc)?;
    let info = hex_bytes(&vector.info)?;
    let psk = Zeroizing::new(hex_bytes(&row.psk)?);
    let psk_id = hex_bytes(&row.psk_id)?;

    let sender = setup_sender_psk_derand(&HpkeDerandPskSenderSetupRequest {
        suite,
        recipient_public_key: &public_key,
        encapsulation_randomness: &randomness,
        info: &info,
        psk: HpkePskRef::new(&psk).map_err(|_| AuditError::Shape)?,
        psk_id: HpkePskIdRef::new(&psk_id).map_err(|_| AuditError::Shape)?,
    })
    .map_err(|_| AuditError::Mismatch)?;
    assert_bytes_eq(&sender.encapsulated_key, &enc)?;
    let receiver = setup_receiver_psk(&HpkePskReceiverSetupRequest {
        suite,
        encapsulated_key: &enc,
        recipient_private_key: &private_key,
        info: &info,
        psk: HpkePskRef::new(&psk).map_err(|_| AuditError::Shape)?,
        psk_id: HpkePskIdRef::new(&psk_id).map_err(|_| AuditError::Shape)?,
    })
    .map_err(|_| AuditError::Mismatch)?;
    Ok((sender, receiver))
}

fn check_vector(vector: &Vector, suite: HpkeSuite) -> Result<(), AuditError> {
    // The public single-shot API always uses the sequence-zero record.
    let record = vector.encryptions.first().ok_or(AuditError::Shape)?;
    let public_key = hex_bytes(&vector.public_key)?;
    let private_key = Zeroizing::new(hex_bytes(&vector.private_key)?);
    let randomness = Zeroizing::new(hex_bytes(&vector.encapsulation_randomness)?);
    let info = hex_bytes(&vector.info)?;
    let enc = hex_bytes(&vector.enc)?;
    let aad = hex_bytes(&record.aad)?;
    let ciphertext = hex_bytes(&record.ct)?;
    let plaintext = Zeroizing::new(hex_bytes(&record.pt)?);

    let sealed = seal_base_derand(&HpkeDerandSealRequest {
        suite,
        recipient_public_key: &public_key,
        encapsulation_randomness: &randomness,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .map_err(|_| AuditError::Mismatch)?;
    assert_bytes_eq(&sealed.encapsulated_key, &enc)?;
    assert_bytes_eq(&sealed.ciphertext, &ciphertext)?;

    let open = HpkeOpenRequest {
        suite,
        encapsulated_key: &enc,
        recipient_private_key: &private_key,
        info: &info,
        aad: &aad,
        ciphertext: &ciphertext,
    };
    let opened = open_base(&open).map_err(|_| AuditError::Mismatch)?;
    assert_bytes_eq(opened.plaintext.as_slice(), &plaintext)?;

    let [first_export, ..] = vector.exports.as_slice() else {
        return Err(AuditError::Shape);
    };
    assert_eq!(vector.exports.len(), 5);
    for export in &vector.exports {
        let context = hex_bytes(&export.exporter_context)?;
        let expected = Zeroizing::new(hex_bytes(&export.exported_value)?);
        if expected.len() != export.length {
            return Err(AuditError::Shape);
        }
        let sender = sender_export_derand(&HpkeDerandSenderExportRequest {
            suite,
            recipient_public_key: &public_key,
            encapsulation_randomness: &randomness,
            info: &info,
            exporter_context: &context,
            output_length: export.length,
        })
        .map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(&sender.encapsulated_key, &enc)?;
        assert_bytes_eq(sender.exporter_secret(), &expected)?;

        let receiver = receiver_export(&HpkeReceiverExportRequest {
            suite,
            encapsulated_key: &enc,
            recipient_private_key: &private_key,
            info: &info,
            exporter_context: &context,
            output_length: export.length,
        })
        .map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(receiver.as_slice(), &expected)?;
    }
    check_rejection(&open, first_export)
}

fn check_rejection(open: &HpkeOpenRequest<'_>, export: &Export) -> Result<(), AuditError> {
    let enc = open.encapsulated_key;
    let context = hex_bytes(&export.exporter_context)?;
    let expected = Zeroizing::new(hex_bytes(&export.exported_value)?);
    let export_request = HpkeReceiverExportRequest {
        suite: open.suite,
        encapsulated_key: enc,
        recipient_private_key: open.recipient_private_key,
        info: open.info,
        exporter_context: &context,
        output_length: export.length,
    };

    // X-Wing puts the ML-KEM ciphertext first. Preserve the wire length and
    // the X25519 component so the change exercises the ML-KEM input alone.
    let mut changed = enc.to_vec();
    *changed.first_mut().ok_or(AuditError::Shape)? ^= 1;
    assert_setup_without_authentication(open, &export_request, &changed, &expected)?;

    if open.suite.kem == HpkeKemId::XWing {
        // The locked backend accepts non-contributory X25519 input during
        // X-Wing decapsulation. The original record must still fail to open.
        let start = enc
            .len()
            .checked_sub(XWING_X25519_ENCAPSULATED_KEY_LEN)
            .ok_or(AuditError::Shape)?;
        let mut noncontributory = enc.to_vec();
        noncontributory
            .get_mut(start..)
            .ok_or(AuditError::Shape)?
            .fill(0);
        assert_setup_without_authentication(open, &export_request, &noncontributory, &expected)?;
    }

    let (_, truncated) = enc.split_last().ok_or(AuditError::Shape)?;
    assert_eq!(
        receiver_export(&HpkeReceiverExportRequest {
            encapsulated_key: truncated,
            ..export_request
        })
        .err(),
        Some(HpkeError::PRIMITIVE_MALFORMED_CIPHERTEXT),
        "short encapsulation for {:?}",
        open.suite,
    );
    assert_eq!(
        open_base(&HpkeOpenRequest {
            encapsulated_key: truncated,
            ..*open
        })
        .err(),
        Some(HpkeError::PRIMITIVE_MALFORMED_CIPHERTEXT),
        "short encapsulation for {:?}",
        open.suite,
    );
    Ok(())
}

fn assert_setup_without_authentication(
    open: &HpkeOpenRequest<'_>,
    export: &HpkeReceiverExportRequest<'_>,
    changed: &[u8],
    expected_export: &[u8],
) -> Result<(), AuditError> {
    // Receiver setup can derive bytes for the changed input. Only the
    // record's AEAD authentication can authorize plaintext release.
    let changed_export = receiver_export(&HpkeReceiverExportRequest {
        encapsulated_key: changed,
        ..*export
    })
    .map_err(|_| AuditError::Mismatch)?;
    assert_eq!(changed_export.as_slice().len(), expected_export.len());
    assert!(changed_export.as_slice() != expected_export);
    assert_eq!(
        open_base(&HpkeOpenRequest {
            encapsulated_key: changed,
            ..*open
        })
        .err(),
        Some(HpkeError::PRIMITIVE_AUTHENTICATION_FAILED),
        "same-length substituted encapsulation for {:?}",
        open.suite,
    );
    Ok(())
}
