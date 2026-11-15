// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use hpke::aead::{Aead, AesGcm128, AesGcm256, ChaCha20Poly1305, ExportOnlyAead};
use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf, KdfShake256};
use hpke::kem::{DhP256HkdfSha256, DhP521HkdfSha512, MlKem768, MlKem1024, X25519HkdfSha256, XWing};
use hpke::schedule_observer::{Schedule, verify, verify_nonce};
use hpke::{
    Deserializable, HpkeError, Kem, OpModeR, OpModeS, PskBundle, Serializable, setup_receiver,
    setup_sender_with_rng,
};
use ml_kem::kem::Decapsulate;
use zeroize::Zeroizing;

// The temporary integration test compiles the production adapter with its
// registered KEM ID and the RFC KEM suite prefix.
mod mlkem512;
mod random;
mod constants {
    pub const HPKE_KEM_ML_KEM_512: u16 = 0x0040;

    pub(crate) const fn encode_kem_suite_id(kem_id: u16) -> [u8; 5] {
        let [high, low] = kem_id.to_be_bytes();
        [b'K', b'E', b'M', high, low]
    }
}

struct ExportVector {
    context: &'static [u8],
    expected: &'static [u8],
}

struct RecordVector {
    nonce: &'static [u8],
    aad: &'static [u8],
    plaintext: &'static [u8],
    ciphertext: &'static [u8],
}

struct Vector {
    suite: (u16, u16, u16),
    recipient_key: &'static [u8],
    recipient_public_key: &'static [u8],
    encapsulation_randomness: &'static [u8],
    enc: &'static [u8],
    info: &'static [u8],
    psk: Option<(&'static [u8], &'static [u8])>,
    schedule: Schedule<'static>,
    exports: &'static [ExportVector],
    export_count: usize,
    records: &'static [RecordVector],
}

const RFC_EXPORT_LENGTH: usize = 32;

static VECTORS: &[Vector] = include!("hpke_schedule_vectors.inc");

struct RejectionVector {
    kem: u16,
    private: &'static [u8],
    enc: &'static [u8],
    original: &'static [u8],
    modified: &'static [u8],
    expected: &'static [u8],
}

static REJECTION_VECTORS: &[RejectionVector] = include!("../hpke_rejection_vectors.inc");

struct XWingClassicalVector {
    private: &'static [u8],
    enc: &'static [u8],
    expected: &'static [u8],
    alternate_enc: &'static [u8],
    alternate: &'static [u8],
}

static X_WING_CLASSICAL_VECTORS: &[XWingClassicalVector] =
    include!("../x_wing_classical_vectors.inc");

#[test]
fn x_wing_decapsulation_matches_independent_classical_substitutions() -> Result<(), HpkeError> {
    const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;
    assert_eq!(X_WING_CLASSICAL_VECTORS.len(), 2);
    for vector in X_WING_CLASSICAL_VECTORS {
        assert_eq!(
            vector.enc[..ML_KEM_768_CIPHERTEXT_BYTES],
            vector.alternate_enc[..ML_KEM_768_CIPHERTEXT_BYTES]
        );
        assert_ne!(
            vector.enc[ML_KEM_768_CIPHERTEXT_BYTES..],
            vector.alternate_enc[ML_KEM_768_CIPHERTEXT_BYTES..]
        );
        let private = <XWing as Kem>::PrivateKey::from_bytes(vector.private)?;
        for (enc, expected) in [
            (vector.enc, vector.expected),
            (vector.alternate_enc, vector.alternate),
        ] {
            let encapsulation = <XWing as Kem>::EncappedKey::from_bytes(enc)?;
            let combined = XWing::decap(&private, None, &encapsulation)?;
            assert!(
                combined.0.as_slice() == expected,
                "combined secret after X25519 substitution"
            );
        }
    }
    Ok(())
}

struct AcvpDecapsulation {
    kem: u16,
    private: &'static [u8],
    enc: &'static [u8],
    expected: &'static [u8],
}

static ACVP_DECAPSULATIONS: &[AcvpDecapsulation] = include!("../ml_kem_acvp_decapsulation.inc");

#[test]
#[allow(deprecated)] // The ACVP vectors supply expanded keys instead of seeds.
fn locked_ml_kem_matches_acvp_rejection_and_valid_controls() -> Result<(), HpkeError> {
    macro_rules! check_acvp {
        ($suite:ident, $vector:expr) => {{
            use ml_kem::$suite::{Ciphertext, DecapsulationKey, ExpandedDecapsulationKey};

            let encoded_private = Zeroizing::new(
                ExpandedDecapsulationKey::try_from($vector.private)
                    .map_err(|_| HpkeError::ValidationError)?,
            );
            let private = DecapsulationKey::from_expanded(&encoded_private)
                .map_err(|_| HpkeError::ValidationError)?;
            let encapsulated =
                Ciphertext::try_from($vector.enc).map_err(|_| HpkeError::ValidationError)?;
            let actual = Zeroizing::new(private.decapsulate(&encapsulated));
            assert!(actual.as_slice() == $vector.expected, "ACVP shared secret");
        }};
    }

    assert_eq!(ACVP_DECAPSULATIONS.len(), 30);
    for vector in ACVP_DECAPSULATIONS {
        match vector.kem {
            0x0040 => check_acvp!(ml_kem_512, vector),
            0x0041 => check_acvp!(ml_kem_768, vector),
            0x0042 => check_acvp!(ml_kem_1024, vector),
            _ => panic!("unexpected ACVP KEM"),
        }
    }
    Ok(())
}

#[test]
fn pq_decapsulation_matches_independent_rejection_bytes() -> Result<(), HpkeError> {
    assert_eq!(REJECTION_VECTORS.len(), 10);
    for vector in REJECTION_VECTORS {
        match vector.kem {
            0x0040 => check_rejection::<mlkem512::MlKem512>(vector)?,
            0x0041 => check_rejection::<MlKem768>(vector)?,
            0x0042 => check_rejection::<MlKem1024>(vector)?,
            0x647a => check_rejection::<XWing>(vector)?,
            _ => panic!("unexpected rejection vector KEM"),
        }
    }
    Ok(())
}

fn check_rejection<K: Kem>(vector: &RejectionVector) -> Result<(), HpkeError> {
    assert_eq!(vector.kem, K::KEM_ID);
    assert_eq!(vector.enc.len(), vector.modified.len());
    let private = K::PrivateKey::from_bytes(vector.private)?;
    let valid = K::EncappedKey::from_bytes(vector.enc)?;
    let rejected = K::EncappedKey::from_bytes(vector.modified)?;
    let success = K::decap(&private, None, &valid)?;
    let fallback = K::decap(&private, None, &rejected)?;
    assert!(
        success.0.as_slice() == vector.original,
        "original KEM shared secret"
    );
    assert!(
        fallback.0.as_slice() == vector.expected,
        "KEM fallback shared secret"
    );
    Ok(())
}

#[test]
fn reference_schedules_exports_and_record_sequences_match() -> Result<(), HpkeError> {
    assert_eq!(VECTORS.len(), 27);
    assert_eq!(
        VECTORS
            .iter()
            .map(|vector| vector.records.len())
            .sum::<usize>(),
        2720
    );
    for vector in VECTORS {
        match vector.suite {
            (0x0010, 0x0001, 0x0001) => check::<AesGcm128, HkdfSha256, DhP256HkdfSha256>(vector)?,
            (0x0010, 0x0001, 0x0002) => check::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(vector)?,
            (0x0012, 0x0003, 0x0002) => check::<AesGcm256, HkdfSha512, DhP521HkdfSha512>(vector)?,
            (0x0020, 0x0001, 0x0001) => check::<AesGcm128, HkdfSha256, X25519HkdfSha256>(vector)?,
            (0x0020, 0x0001, 0x0003) => {
                check::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(vector)?
            }
            (0x0020, 0x0001, 0xffff) => {
                check::<ExportOnlyAead, HkdfSha256, X25519HkdfSha256>(vector)?
            }
            (0x0040, 0x0001, 0x0001) => check::<AesGcm128, HkdfSha256, mlkem512::MlKem512>(vector)?,
            (0x0041, 0x0001, 0x0001) => check::<AesGcm128, HkdfSha256, MlKem768>(vector)?,
            (0x0042, 0x0002, 0x0002) => check::<AesGcm256, HkdfSha384, MlKem1024>(vector)?,
            (0x647a, 0x0001, 0x0003) => check::<ChaCha20Poly1305, HkdfSha256, XWing>(vector)?,
            (0x647a, 0x0011, 0x0003) => check::<ChaCha20Poly1305, KdfShake256, XWing>(vector)?,
            _ => panic!("unexpected HPKE audit suite"),
        }
    }
    Ok(())
}

fn check<A: Aead, F: Kdf, K: Kem>(vector: &'static Vector) -> Result<(), HpkeError> {
    assert_eq!(vector.suite, (K::KEM_ID, F::KDF_ID, A::AEAD_ID));
    let key = K::PrivateKey::from_bytes(vector.recipient_key)?;
    let enc = K::EncappedKey::from_bytes(vector.enc)?;
    let mode = match vector.psk {
        None => OpModeR::Base,
        Some((psk, id)) => OpModeR::Psk(PskBundle::new(psk, id)?),
    };
    let mut receiver = verify(&vector.schedule, || {
        setup_receiver::<A, F, K>(&mode, &key, &enc, vector.info)
    })?;
    assert_eq!(vector.exports.len(), vector.export_count);
    for (index, export) in vector.exports.iter().enumerate() {
        assert_eq!(export.expected.len(), RFC_EXPORT_LENGTH);
        let mut output = Zeroizing::new([0_u8; RFC_EXPORT_LENGTH]);
        receiver.export(export.context, &mut output[..])?;
        assert!(output.as_slice() == export.expected, "export value {index}");
    }

    if vector.records.is_empty() {
        return Ok(());
    }

    let mode = match vector.psk {
        None => OpModeS::Base,
        Some((psk, id)) => OpModeS::Psk(PskBundle::new(psk, id)?),
    };
    let key = K::PublicKey::from_bytes(vector.recipient_public_key)?;
    let mut rng = random::FixedRandomness::new(vector.encapsulation_randomness);
    let (actual_enc, mut sender) = verify(&vector.schedule, || {
        setup_sender_with_rng::<A, F, K>(&mode, &key, vector.info, &mut rng)
    })?;
    assert!(
        rng.was_consumed_exactly(),
        "unexpected KEM randomness length"
    );
    assert!(
        actual_enc.to_bytes().as_slice() == vector.enc,
        "encapsulation"
    );

    // Keep one live sender and receiver per row. Recreating either context
    // for each record would skip the production sequence transitions.
    for (index, record) in vector.records.iter().enumerate() {
        let ciphertext = verify_nonce(record.nonce, || sender.seal(record.plaintext, record.aad))?;
        assert!(ciphertext == record.ciphertext, "sealed record {index}");

        let mut invalid = record.ciphertext.to_vec();
        *invalid
            .last_mut()
            .expect("vector generator checks tag length") ^= 1;
        let failure = verify_nonce(record.nonce, || receiver.open(&invalid, record.aad));
        assert_eq!(
            failure.map(Zeroizing::new).err(),
            Some(HpkeError::OpenError),
            "invalid tag on record {index}"
        );

        let plaintext = Zeroizing::new(verify_nonce(record.nonce, || {
            receiver.open(record.ciphertext, record.aad)
        })?);
        assert!(
            plaintext.as_slice() == record.plaintext,
            "opened record {index}"
        );
    }
    Ok(())
}
