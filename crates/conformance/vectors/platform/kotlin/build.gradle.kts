// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

plugins {
    kotlin("jvm") version "2.4.0"
}

group = "me.really"
version = "0.1.1"

kotlin {
    jvmToolchain(21)
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.84")
    testImplementation("fr.acinq.secp256k1:secp256k1-kmp-jvm:0.23.0")
    testImplementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.23.0")
}

tasks.test {
    useJUnitPlatform()
    systemProperty(
        "reallyme.crypto.vectors.dir",
        providers.environmentVariable("REALLYME_CRYPTO_VECTORS_DIR").orElse(
            layout.projectDirectory.dir("../../../../../vectors").asFile.absolutePath
        ).get()
    )
}
