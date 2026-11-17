// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent known-answer coverage for the post-quantum HPKE profiles used by MLS.
//!
//! The inputs and expected ciphertexts are from the immutable published
//! `draft-ietf-hpke-pq-05`, Appendices A.2, A.3, A.4, and A.6:
//! <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.txt>.

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(all(feature = "native", feature = "test-vectors"))]

use crypto_hpke::{
    derive_keypair_from_ikm, open_base, seal_base_derand, HpkeAeadId, HpkeDerandSealRequest,
    HpkeKdfId, HpkeKemId, HpkeOpenRequest, HpkeSuite, HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM,
    HPKE_MLKEM1024_HKDF_SHA384_AES256GCM, HPKE_MLKEM768_HKDF_SHA384_AES256GCM,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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
fn ml_kem_768_p256_matches_hpke_pq_draft_vector() {
    // Appendix A.4 supplies the full 160-byte sender input, including unused
    // P-256 candidates. Matching its ciphertext checks more than a round trip
    // through two implementations with the same entropy-consumption mistake.
    let suite = HpkeSuite::new(
        HpkeKemId::MlKem768P256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes128Gcm,
    );
    let recipient_ikm = Zeroizing::new(decode(
        "3bf888035cc5f48fa476c2ccdb73a5482e97a0d0578fa710b1e393ca9716b6f0",
    ));
    let sender_ikm = Zeroizing::new(decode(concat!(
        "60bb82b558667cd90fdaa6dad511b68ecc36c74aaba659838978c2f1f6e9194f",
        "e391cdcd5aaf218bd2132ee45652de419faeff24b210dcdefd78db2f4d80757d",
        "c026148067910f470240b079c36f31463f43a33962585e1a84f6230384071be6",
        "9eac96ecf1ff4b4b4be510631406690c62c037d7ab2623ae4980c5885284d8b6",
        "10e446eb79b5b6ecbc914ed3b924db036e8604569bec37093231d13bf31eb9df"
    )));
    assert_eq!(suite.encapsulation_randomness_len(), Ok(160));
    assert_eq!(sender_ikm.len(), 160);
    let recipient = derive_keypair_from_ikm(suite, &recipient_ikm)
        .expect("published recipient IKM must derive");
    assert_eq!(
        recipient.private_key(),
        Zeroizing::new(decode(
            "1f25a59a6b22ef57b8e48a6cfe739b9ec13e9cf57e82dfd6e0480e0324cf905b"
        ))
        .as_slice()
    );
    let info = decode(INFO_HEX);
    let aad = decode(AAD_HEX);
    let plaintext = Zeroizing::new(decode(PLAINTEXT_HEX));
    let sealed = seal_base_derand(&HpkeDerandSealRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: &sender_ikm,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .expect("published sender randomness must encapsulate");
    assert_eq!(
        hex::encode(&sealed.ciphertext),
        concat!(
            "c55b375ecf13081a2448aefca58ca81ba771e04bc7299f9152aded351c76ac05cd",
            "c985a1609335f1399855f528adb21f48dfcc841fd7ef1c38bc64d9bdcd9c18c68d",
            "6d7a6c247429677d"
        )
    );
    let opened = open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info: &info,
        aad: &aad,
        ciphertext: &sealed.ciphertext,
    })
    .expect("published ciphertext must open");
    assert_eq!(opened.plaintext.as_slice(), plaintext.as_slice());
}

#[test]
fn ml_kem_768_kem_matches_hpke_pq_draft_vector() {
    // draft-ietf-hpke-pq-05, Appendix A.2. The published profile uses
    // HKDF-SHA256 and AES-128-GCM, while MLS draft-06 combines the same KEM
    // with HKDF-SHA384 and AES-256-GCM. Key derivation and encapsulation are
    // KEM operations, so their complete-value commitments remain applicable;
    // the ciphertext below is intentionally checked by round-trip instead of
    // being described as an exact Appendix A.2 HPKE ciphertext vector.
    let recipient_ikm = decode(concat!(
        "a60b35f174ce9ac7a4ff5b9f81e38125b03506ecbd56a3a55c31ece0f5907052",
        "0729773a61a499d5137daaef824b493848b6e4dd332a815ff19aa9f58a381eb8"
    ));
    let sender_ikm = decode("9b933cd9c9421cd58db0c5f6cea53eedbd7fae056ff95d688d8ed9a58177e76b");
    let recipient = derive_keypair_from_ikm(HPKE_MLKEM768_HKDF_SHA384_AES256GCM, &recipient_ikm)
        .expect("published recipient IKM must derive");
    assert_eq!(
        sha256_hex(&recipient.public_key),
        "80aabb142999e683475598517f3bca6b9b8c8f01109ec8f861b450d2a8b9148d"
    );
    assert_eq!(
        sha256_hex(recipient.private_key()),
        "386aeafcaac84b3ae7227e02d6ca8a77b5b909866fe8542e5e84dd7bc14dba9b"
    );

    let info = decode(INFO_HEX);
    let aad = decode(AAD_HEX);
    let plaintext = decode(PLAINTEXT_HEX);
    let sealed = seal_base_derand(&HpkeDerandSealRequest {
        suite: HPKE_MLKEM768_HKDF_SHA384_AES256GCM,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: &sender_ikm,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .expect("published sender IKM must encapsulate");
    assert_eq!(
        sha256_hex(&sealed.encapsulated_key),
        "48f93a13c1ee2be820054837dae8c60bb9fdec23347521ec8b81d0e4716a649c"
    );

    let opened = open_base(&HpkeOpenRequest {
        suite: HPKE_MLKEM768_HKDF_SHA384_AES256GCM,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info: &info,
        aad: &aad,
        ciphertext: &sealed.ciphertext,
    })
    .expect("MLS-profile ciphertext must open");
    assert_eq!(opened.plaintext.as_slice(), plaintext);
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
