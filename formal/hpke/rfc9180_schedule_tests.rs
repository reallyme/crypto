// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use hpke::aead::{Aead, AesGcm128, AesGcm256, ChaCha20Poly1305, ExportOnlyAead};
use hpke::kdf::{HkdfSha256, HkdfSha512, Kdf};
use hpke::kem::{DhP256HkdfSha256, DhP521HkdfSha512, X25519HkdfSha256};
use hpke::schedule_observer::{Schedule, verify};
use hpke::{Deserializable, HpkeError, Kem, OpModeR, PskBundle, setup_receiver};
use zeroize::Zeroizing;

struct ExportVector {
    context: &'static [u8],
    expected: &'static [u8],
}

struct Vector {
    suite: (u16, u16, u16),
    recipient_key: &'static [u8],
    enc: &'static [u8],
    info: &'static [u8],
    psk: Option<(&'static [u8], &'static [u8])>,
    schedule: Schedule<'static>,
    exports: &'static [ExportVector],
}

const RFC_EXPORT_LENGTH: usize = 32;

static VECTORS: &[Vector] = include!("rfc9180_schedule_vectors.inc");

#[test]
fn rfc9180_key_schedule_and_exports_match() -> Result<(), HpkeError> {
    assert_eq!(VECTORS.len(), 12);
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
            _ => panic!("unexpected RFC 9180 audit suite"),
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
    let context = verify(&vector.schedule, || {
        setup_receiver::<A, F, K>(&mode, &key, &enc, vector.info)
    })?;
    assert_eq!(vector.exports.len(), 3);
    for (index, export) in vector.exports.iter().enumerate() {
        assert_eq!(export.expected.len(), RFC_EXPORT_LENGTH);
        let mut output = Zeroizing::new([0_u8; RFC_EXPORT_LENGTH]);
        context.export(export.context, &mut output[..])?;
        assert!(output.as_slice() == export.expected, "export value {index}");
    }
    Ok(())
}
