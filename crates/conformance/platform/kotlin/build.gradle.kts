// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

buildscript {
    configurations.classpath {
        resolutionStrategy.activateDependencyLocking()
    }
}

plugins {
    kotlin("jvm") version "2.4.21"
}

group = "me.really"
version = "0.4.6"

dependencyLocking {
    lockAllConfigurations()
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.87")
    testImplementation("fr.acinq.secp256k1:secp256k1-kmp-jvm:0.24.0")
    testImplementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.24.0")
}

tasks.test {
    useJUnitPlatform()
    systemProperty(
        "reallyme.crypto.vectors.dir",
        providers.environmentVariable("REALLYME_CRYPTO_VECTORS_DIR").orElse(
            layout.projectDirectory.dir("../../../../vectors").asFile.absolutePath
        ).get()
    )
}
