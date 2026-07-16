// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ReallyMeCryptoAndroidInstrumentedTest {
    @Test
    fun aesGcmRoundTripsOnAndroidProviderLane() {
        val key = ByteArray(ReallyMeAesGcm.KEY_LENGTH) { index -> index.toByte() }
        val nonce = ByteArray(ReallyMeAesGcm.NONCE_LENGTH) { index -> (index + 16).toByte() }
        val aad = "reallyme-android-aead".toByteArray(Charsets.UTF_8)
        val plaintext = "android runtime provider smoke".toByteArray(Charsets.UTF_8)

        val sealed = ReallyMeCrypto.seal(
            ReallyMeAeadAlgorithm.AES_256_GCM,
            key,
            nonce,
            aad,
            plaintext,
        )
        val opened = ReallyMeCrypto.open(
            ReallyMeAeadAlgorithm.AES_256_GCM,
            key,
            nonce,
            aad,
            sealed,
        )

        assertArrayEquals(plaintext, opened)
    }

    @Test
    fun aesKwUsesBundledBouncyCastleProviderOnAndroid() {
        val wrappingKey = ByteArray(ReallyMeAesKw.WRAPPING_KEY_LENGTH) { index -> (index + 1).toByte() }
        val keyToWrap = ByteArray(ReallyMeAesKw.MIN_KEY_DATA_LENGTH) { index -> (index + 33).toByte() }
        val cipher = ReallyMeJceProviders.bouncyCastleCipher("AESWrap")

        assertTrue(ReallyMeJceProviders.isBundledBouncyCastleProvider(cipher.provider))
        val wrapped = ReallyMeCrypto.wrapKey(
            ReallyMeKeyWrapAlgorithm.AES_256_KW,
            wrappingKey,
            keyToWrap,
        )
        val unwrapped = ReallyMeCrypto.unwrapKey(
            ReallyMeKeyWrapAlgorithm.AES_256_KW,
            wrappingKey,
            wrapped,
        )

        assertArrayEquals(keyToWrap, unwrapped)
    }

    @Test
    fun rsaPkcs1v15AndPssVerifyOnAndroid() {
        val publicKeyDer = base64UrlBytes(
            "MIIBCgKCAQEAtLGfC3GxzVAbnFDLYwUlIB52PJUl3yVGcY2X-3vFcQsbOhdYKVW7Ug1G0-adGVsz7Sl4" +
                "CAVZCgDy9LVawN6Wl5TUj8_obkDrtKv9srFmUm0OfYP4REpZq0OBKAs6jf5E5aHqe09edvsO3LOJt" +
                "VqhHgtFM_xvobGr4TtaPGSoFjssvzJ9YVyK08xDOhCaT4K6ukKlaKBTiOjgVxUtmDRnzct--bNxkh" +
                "J88ObqNyJTbp78FWKMsKNfJCTVnKnQIdDMCCQgS6AIXm_d2bPK6FrvDphqfem9ysGQaqPeZjCCoEU9" +
                "lF9ha_v29bQn6CPxzT7cCYW8V-J_mqhOIwqocTI7jQIDAQAB",
        )
        val message = base64UrlBytes("UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg")
        val pkcs1v15Sha256Signature = base64UrlBytes(
            "Re77CuddLv7YajqprynKArLWsc_5tMp5UOAgi1M4cHgj9lKJ14VuI78Lx4if-ngxz4hDxwbRMOh0" +
                "V50DkRYcd_oyfdzecsqo-SisuGGGer5gWJ8h2_8wyrKuSXroNt2CyPUGv5Jn6K5I9krL6Cx0U7_" +
                "MyE6HZJNSVH1w6VpxNsf8iNvp-p_eFkt8dEVuBFxsNlGQV3ltFNVg99kBDOiammOuXIrkCf_V67" +
                "xy3Hc2RkptbmNHTnlC8hw8WBoMH5ds5UcYMuHVgRr8CmXr4YNX9Vel46L7UV69FN5xcJNTLEW0_" +
                "Ylo9N_Csh8urYUbupfvZ49uWMOzyReMg4tzu90lSw",
        )
        val pssSha256Signature = base64UrlBytes(
            "bYeyCHaW_4vy7QDQlAtm7fY5CV9XH4Kt0eINKPRd9E1YFrvI2KLaVgG7-T0uGPu8P_t3BV0n_" +
                "FJJBRxMlSySqFqT_VllgzXuBJ3A7fC_pFyMPK6A3XZ0Y_3rWShvjeZnBf_doMSjoGuWFSaB0K4" +
                "IOAiyjyoJ3RGea6ikt-5nGPvaiFb6K3YXZTJXavH8AKu3J19V2kTrUGHZ6Lf5RuqWHFyzFsEz" +
                "NPcp13ezECkVMZHQEwLxt9Li_mWqXDhPF4bpPCUpGljfmsgqo0RBYogEau7YxqaS15-HhLhWT" +
                "aJYGEcvWBL9burCgU4nlqfEt9gU0m2EDhhUGR38CS86RSiwEw",
        )

        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA256,
            pkcs1v15Sha256Signature,
            message,
            publicKeyDer,
            ReallyMeRsaPublicKeyDerEncoding.PKCS1,
        )
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA256_MGF1_SHA256,
            pssSha256Signature,
            message,
            publicKeyDer,
            ReallyMeRsaPublicKeyDerEncoding.PKCS1,
        )
    }

    @Test
    fun rustJniArgon2idRouteLoadsFromBundledAndroidLibrary() {
        assertEquals(ReallyMeNativeStatus.OK, ReallyMeRustNativeProvider.loadBundledLibraryStatus())
        val derived = ReallyMeArgon2id.deriveKey(
            ReallyMeArgon2id.V1,
            "android-rust-jni-secret".toByteArray(Charsets.UTF_8),
            "reallyme-argon2id-salt".toByteArray(Charsets.UTF_8),
        )

        assertEquals(ReallyMeArgon2id.DERIVED_KEY_LENGTH, derived.size)
    }

    @Test
    fun bip340SchnorrSignsAndVerifiesOnAndroidSecp256k1Lane() {
        val secretKey = ByteArray(ReallyMeBip340Schnorr.SECRET_KEY_LENGTH) { index -> (index + 1).toByte() }
        val publicKey = ReallyMeBip340Schnorr.derivePublicKey(secretKey)
        val message = ByteArray(ReallyMeBip340Schnorr.MESSAGE_LENGTH) { index -> (index + 64).toByte() }
        val auxRand = ByteArray(ReallyMeBip340Schnorr.AUX_RAND_LENGTH) { index -> (index + 96).toByte() }
        val signature = ReallyMeCrypto.signBip340Schnorr(message, secretKey, auxRand)

        assertEquals(ReallyMeBip340Schnorr.PUBLIC_KEY_LENGTH, publicKey.size)
        assertEquals(ReallyMeBip340Schnorr.SIGNATURE_LENGTH, signature.size)
        ReallyMeCrypto.verify(ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256, signature, message, publicKey)
    }

    private fun base64UrlBytes(encoded: String): ByteArray =
        Base64.decode(encoded, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}
