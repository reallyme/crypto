// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Independent known-answer coverage for the post-quantum HPKE profiles used by MLS.
//!
//! The inputs and expected ciphertexts are from the immutable published
//! `draft-ietf-hpke-pq-05`, Appendices A.3 and A.6:
//! <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.txt>.

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(all(feature = "native", feature = "test-vectors"))]

use crypto_hpke::{
    derive_keypair_from_ikm, open_base, seal_base_derand, HpkeDerandSealRequest, HpkeOpenRequest,
    HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM, HPKE_MLKEM1024_HKDF_SHA384_AES256GCM,
};
use sha2::{Digest, Sha256};

const INFO_HEX: &str =
    "34663634363532303666366532303631323034373732363536333639363136653230353537323665";
const AAD_HEX: &str = "436f756e742d30";
const PLAINTEXT_HEX: &str = concat!(
    "3432363536313735373437393230363937333230373437323735373436383263",
    "3230373437323735373436383230363236353631373537343739"
);

fn decode(encoded: &str) -> Vec<u8> {
    hex::decode(encoded).expect("published vector must contain valid hexadecimal")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn ml_kem_1024_hkdf_sha384_matches_hpke_pq_draft_vector() {
    // draft-ietf-hpke-pq-05, Appendix A.3. The SHA-256 commitments bind the
    // complete fixed-size key and encapsulation values without embedding more
    // than six kilobytes of deterministic key material in this test.
    let recipient_ikm = decode(concat!(
        "d6688a981deeff1d1273426af8a44aab877c50b6e8ac74b11e01a5960d97c03b",
        "ffd9634894d255c424c80c74e0930b85b9f4c60e22a3efb09f4bad4749be427b"
    ));
    let sender_ikm = decode("54e68c4d0f72b94d956acf637c23570e505db5c08c0068bd136cacbc7dedda89");
    let recipient = derive_keypair_from_ikm(HPKE_MLKEM1024_HKDF_SHA384_AES256GCM, &recipient_ikm)
        .expect("published recipient IKM must derive");
    assert_eq!(
        sha256_hex(&recipient.public_key),
        "b45440fa44f6a7046ecf45d77fdd4fd9f02982defa787501ba365f0c264d9f73"
    );
    assert_eq!(
        sha256_hex(recipient.private_key()),
        "e328f149f09f5414295528ea27cc9e17e6de6eb7647bfda19c36a828118cf05b"
    );

    let info = decode(INFO_HEX);
    let aad = decode(AAD_HEX);
    let plaintext = decode(PLAINTEXT_HEX);
    let sealed = seal_base_derand(&HpkeDerandSealRequest {
        suite: HPKE_MLKEM1024_HKDF_SHA384_AES256GCM,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: &sender_ikm,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .expect("published sender IKM must encapsulate");
    assert_eq!(
        sha256_hex(&sealed.encapsulated_key),
        "235e148aedf1e71805c8a5cb20555a45e427a0adbf5d22150531fa653287211b"
    );
    assert_eq!(
        hex::encode(&sealed.ciphertext),
        concat!(
            "9d16979cb9ac997886c0ec51ed2c049d7ec53b369467026157ef061af23695b9",
            "96e1893afd2173c310546859e82eea9c16e0a1363bc994f2ff708e5d60089c1b",
            "233f38ce6a7fbd176744"
        )
    );

    let opened = open_base(&HpkeOpenRequest {
        suite: HPKE_MLKEM1024_HKDF_SHA384_AES256GCM,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info: &info,
        aad: &aad,
        ciphertext: &sealed.ciphertext,
    })
    .expect("published ciphertext must open");
    assert_eq!(opened.plaintext.as_slice(), plaintext);
}

#[test]
fn ml_kem_1024_p384_hkdf_sha384_matches_hpke_pq_draft_vector() {
    // draft-ietf-hpke-pq-05, Appendix A.6. This vector independently covers
    // hybrid key derivation, encapsulation, the KEM combiner, and HPKE state.
    let recipient_ikm = decode("14c036a5e3c4af452baccdcd62cf818f250607076c299636e5c8074b3c757df1");
    let sender_ikm = decode(concat!(
        "a2aa5d3e682abee327d4d258e47fdf9b987efc96a15e1f11fd81413206d1ae2a",
        "b11e0d808cb65a680cf32b00eed796e02d149f3454974db3e1751cf2fc1916e0",
        "d887c307c18b28645809760d00d6191a"
    ));
    let recipient =
        derive_keypair_from_ikm(HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM, &recipient_ikm)
            .expect("published hybrid recipient IKM must derive");
    assert_eq!(
        sha256_hex(&recipient.public_key),
        "2fa438cda8bdfa993e8286a31a3c7d90766dacd114131cd5dfecf466eab936e3"
    );
    assert_eq!(
        sha256_hex(recipient.private_key()),
        "03f254652cbe6905cf09edf590fc6a830910bfe69534231eb46e50b8f2de9776"
    );

    let info = decode(INFO_HEX);
    let aad = decode(AAD_HEX);
    let plaintext = decode(PLAINTEXT_HEX);
    let sealed = seal_base_derand(&HpkeDerandSealRequest {
        suite: HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: &sender_ikm,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .expect("published hybrid sender IKM must encapsulate");
    assert_eq!(
        sha256_hex(&sealed.encapsulated_key),
        "dca2c5ed53db453080df9de9e7d38191d10f8362fc9b47c57650c357ed99588c"
    );
    assert_eq!(
        hex::encode(&sealed.ciphertext),
        concat!(
            "1af5c6176d191f913bb9a39ae6af2c5847d5effca2d794242de5464ef287bfd6",
            "d5f6735bab1b42b3d29a6b131a91b180b04dbf6afc395bdc35f2b8558db9c6",
            "2ce54c81872b42d222459a"
        )
    );

    let opened = open_base(&HpkeOpenRequest {
        suite: HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info: &info,
        aad: &aad,
        ciphertext: &sealed.ciphertext,
    })
    .expect("published hybrid ciphertext must open");
    assert_eq!(opened.plaintext.as_slice(), plaintext);
}
