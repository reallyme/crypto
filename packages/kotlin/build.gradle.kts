// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import org.gradle.external.javadoc.StandardJavadocDocletOptions

plugins {
    kotlin("jvm") version "2.4.0"
    `java-library`
    `maven-publish`
    signing
}

group = "me.really"
version = "0.1.6"

val remoteMavenRepositoryUrl = providers.gradleProperty("reallyme.maven.repositoryUrl")
    .orElse(providers.environmentVariable("REALLYME_MAVEN_REPOSITORY_URL"))
val remoteMavenUsername = providers.gradleProperty("reallyme.maven.username")
    .orElse(providers.environmentVariable("REALLYME_MAVEN_USERNAME"))
val remoteMavenPassword = providers.gradleProperty("reallyme.maven.password")
    .orElse(providers.environmentVariable("REALLYME_MAVEN_PASSWORD"))
val signingKey = providers.gradleProperty("signingInMemoryKey")
    .orElse(providers.environmentVariable("MAVEN_SIGNING_KEY"))
val signingPassword = providers.gradleProperty("signingInMemoryKeyPassword")
    .orElse(providers.environmentVariable("MAVEN_SIGNING_PASSWORD"))

kotlin {
    jvmToolchain(21)
    sourceSets {
        main {
            kotlin.srcDir("../../gen/kotlin")
        }
    }
}

java {
    withSourcesJar()
    withJavadocJar()
}

sourceSets {
    named("main") {
        java.srcDir("../../gen/java")
    }
}

dependencies {
    api("com.google.protobuf:protobuf-javalite:4.35.1")
    api("com.google.protobuf:protobuf-kotlin-lite:4.35.1")
    // Same pinned BouncyCastle the Kotlin conformance lane proves vectors
    // against; the SDK and the oracle must not drift apart.
    implementation("org.bouncycastle:bcprov-jdk18on:1.84")
    // secp256k1 ECDSA and BIP-340 Schnorr are backed by Bitcoin Core
    // libsecp256k1 (the constant-time reference implementation) via ACINQ's
    // JNI bindings. This is the same C library the Swift lane uses through
    // CSecp256k1, so signatures are byte-identical across lanes and no EC
    // scalar math is hand-rolled. The `-jni-jvm` artifact bundles desktop
    // natives; an Android consumer swaps it for `secp256k1-kmp-jni-android`.
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jvm:0.23.0")
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.23.0")

    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
    val ffiLibraryPath = providers.environmentVariable("REALLYME_CRYPTO_FFI_LIBRARY_PATH")
    if (ffiLibraryPath.isPresent) {
        systemProperty("java.library.path", file(ffiLibraryPath.get()).parent)
    }
}

tasks.withType<Javadoc>().configureEach {
    val standardOptions = options as StandardJavadocDocletOptions
    standardOptions.addStringOption("Xdoclint:none", "-quiet")
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "crypto"
            from(components["java"])
            pom {
                name.set("ReallyMe Crypto")
                description.set(
                    "Cross-platform cryptography compatibility facade for Kotlin, JVM, and Android."
                )
                url.set("https://github.com/reallyme/crypto")
                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        id.set("reallyme")
                        name.set("ReallyMe LLC")
                        organization.set("ReallyMe LLC")
                        organizationUrl.set("https://github.com/reallyme")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/reallyme/crypto.git")
                    developerConnection.set("scm:git:ssh://git@github.com/reallyme/crypto.git")
                    url.set("https://github.com/reallyme/crypto")
                }
            }
        }
    }
    repositories {
        maven {
            name = "localRelease"
            url = layout.buildDirectory.dir("repos/releases").get().asFile.toURI()
        }
        if (remoteMavenRepositoryUrl.isPresent) {
            maven {
                name = "remoteRelease"
                url = uri(remoteMavenRepositoryUrl.get())
                credentials {
                    username = remoteMavenUsername.orNull
                    password = remoteMavenPassword.orNull
                }
            }
        }
    }
}

signing {
    if (signingKey.isPresent) {
        useInMemoryPgpKeys(signingKey.get(), signingPassword.orNull)
        sign(publishing.publications["maven"])
    }
}
