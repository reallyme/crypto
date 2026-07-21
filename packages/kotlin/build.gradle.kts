// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.publish.maven.tasks.PublishToMavenLocal
import org.gradle.api.publish.maven.tasks.PublishToMavenRepository
import org.gradle.external.javadoc.StandardJavadocDocletOptions
import org.gradle.jvm.tasks.Jar
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

plugins {
    kotlin("jvm") version "2.4.0"
    `java-library`
    `maven-publish`
    signing
}

group = "me.really"
version = "0.3.0"

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
val requireRemoteMavenPublishing = providers.gradleProperty("reallyme.maven.requireRemote")
    .map { it == "true" }
    .orElse(false)

fun nonBlank(value: String?): String? = value?.trim()?.takeIf { it.isNotEmpty() }

fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

val remoteMavenRepositoryUrlValue = nonBlank(remoteMavenRepositoryUrl.orNull)
val remoteMavenUsernameValue = nonBlank(remoteMavenUsername.orNull)
val remoteMavenPasswordValue = nonBlank(remoteMavenPassword.orNull)
val signingKeyValue = nonBlank(signingKey.orNull)
val signingPasswordValue = nonBlank(signingPassword.orNull)
val configuredNativeResourcesDir = providers.gradleProperty("reallyme.crypto.nativeResourcesDir")
val nativeResourcesDir = configuredNativeResourcesDir
    .map { file(it) }
    .orElse(layout.buildDirectory.dir("generated/native-resources").map { it.asFile })
val requireFullNativeResources = providers.gradleProperty("reallyme.crypto.requireFullNativeResources")
    .map { it == "true" }
    .orElse(false)
val requiredNativeResources = listOf(
    "me/really/crypto/native/linux-x86_64/libcrypto_ffi.so",
    "me/really/crypto/native/linux-aarch64/libcrypto_ffi.so",
    "me/really/crypto/native/macos-x86_64/libcrypto_ffi.dylib",
    "me/really/crypto/native/macos-aarch64/libcrypto_ffi.dylib",
    "me/really/crypto/native/windows-x86_64/crypto_ffi.dll",
    "me/really/crypto/native/native-manifest.json",
)
val maxNativeResourceEntries = 64

fun nativeResourcePaths(root: File): Set<String> {
    if (!root.isDirectory || Files.isSymbolicLink(root.toPath())) {
        throw GradleException("ReallyMe crypto native resource root is not a regular directory")
    }
    val paths = mutableSetOf<String>()
    var entryCount = 0
    root.walkTopDown().forEach { entry ->
        if (entry == root) {
            return@forEach
        }
        entryCount += 1
        if (entryCount > maxNativeResourceEntries) {
            throw GradleException("ReallyMe crypto native resource tree contains too many entries")
        }
        if (Files.isSymbolicLink(entry.toPath())) {
            throw GradleException("ReallyMe crypto native resource tree contains a symbolic link")
        }
        if (entry.isFile) {
            paths.add(entry.relativeTo(root).invariantSeparatorsPath)
        } else if (!entry.isDirectory) {
            throw GradleException("ReallyMe crypto native resource tree contains an unsupported entry")
        }
    }
    return paths
}

fun verifyExactNativeResources(root: File, expectedPaths: Set<String>) {
    if (nativeResourcePaths(root) != expectedPaths) {
        throw GradleException("ReallyMe crypto native resources do not match the exact required file set")
    }
}

val hostNativePlatform = when {
    System.getProperty("os.name").contains("Mac", ignoreCase = true) -> "macos"
    System.getProperty("os.name").contains("Linux", ignoreCase = true) -> "linux"
    System.getProperty("os.name").contains("Windows", ignoreCase = true) -> "windows"
    else -> null
}
val hostNativeArch = when (System.getProperty("os.arch").lowercase()) {
    "aarch64", "arm64" -> "aarch64"
    "amd64", "x86_64" -> "x86_64"
    else -> null
}
val hostNativeLibraryName = when (hostNativePlatform) {
    "macos" -> "libcrypto_ffi.dylib"
    "windows" -> "crypto_ffi.dll"
    "linux" -> "libcrypto_ffi.so"
    else -> "unsupported-native-library"
}
val hostNativeSupported = hostNativePlatform != null && hostNativeArch != null
val requiredHostNativeResource = if (hostNativeSupported) {
    "me/really/crypto/native/$hostNativePlatform-$hostNativeArch/$hostNativeLibraryName"
} else {
    null
}

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
        resources.srcDir(nativeResourcesDir)
    }
}

val buildHostNativeLibrary = tasks.register<Exec>("buildHostNativeLibrary") {
    group = "build"
    description = "Builds the host Rust JNI library for local JVM tests."
    onlyIf { !configuredNativeResourcesDir.isPresent && hostNativeSupported }
    workingDir = layout.projectDirectory.dir("../..").asFile
    // Match release packaging and prevent ambient codegen flags from silently
    // disabling the native panic firewall during JVM integration tests.
    environment("RUSTFLAGS", "")
    environment("CARGO_ENCODED_RUSTFLAGS", "")
    commandLine(
        "cargo",
        "build",
        "-p",
        "crypto-ffi",
        "--profile",
        "release-ffi",
    )
}

val stageHostNativeResource = tasks.register<Copy>("stageHostNativeResource") {
    group = "build"
    description = "Stages the host Rust JNI library as a JVM package resource for local tests."
    onlyIf { !configuredNativeResourcesDir.isPresent && hostNativeSupported }
    dependsOn(buildHostNativeLibrary)
    from(layout.projectDirectory.file("../../target/release-ffi/$hostNativeLibraryName"))
    into(nativeResourcesDir.map {
        it.resolve("me/really/crypto/native/$hostNativePlatform-$hostNativeArch")
    })
}

val writeHostNativeManifest = tasks.register("writeHostNativeManifest") {
    group = "build"
    description = "Writes the host native checksum manifest for local JVM tests."
    onlyIf { !configuredNativeResourcesDir.isPresent && hostNativeSupported }
    dependsOn(stageHostNativeResource)
    val manifestFile = nativeResourcesDir.map {
        it.resolve("me/really/crypto/native/native-manifest.json")
    }
    val stagedLibraryFile = nativeResourcesDir.map {
        it.resolve("me/really/crypto/native/$hostNativePlatform-$hostNativeArch/$hostNativeLibraryName")
    }
    inputs.file(stagedLibraryFile)
    outputs.file(manifestFile)
    doLast {
        if (!hostNativeSupported) {
            throw GradleException("unsupported host platform for ReallyMe crypto JNI resources")
        }
        val library = stagedLibraryFile.get()
        val bytes = library.readBytes()
        val relativePath = "$hostNativePlatform-$hostNativeArch/$hostNativeLibraryName"
        manifestFile.get().writeText(
            """
            {
              "schemaVersion": 1,
              "package": "reallyme-crypto-native",
              "commitSha": "local-test",
              "entries": [
                {
                  "path": "$relativePath",
                  "sha256": "${sha256Hex(bytes)}",
                  "size": ${bytes.size}
                }
              ]
            }
            """.trimIndent(),
        )
    }
}

dependencies {
    implementation("com.google.code.gson:gson:2.11.0")
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
    implementation("me.really:codec:0.2.0")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.11.4")
    testImplementation(kotlin("test"))
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.4")
}

tasks.test {
    useJUnitPlatform()
    val ffiLibraryPath = providers.environmentVariable("REALLYME_CRYPTO_FFI_LIBRARY_PATH")
    if (ffiLibraryPath.isPresent) {
        systemProperty("java.library.path", file(ffiLibraryPath.get()).parent)
    }
    val codecFfiLibraryPath = providers.environmentVariable("REALLYME_CODEC_FFI_LIBRARY_PATH")
    if (codecFfiLibraryPath.isPresent) {
        systemProperty("reallyme.codec.ffiLibraryPath", codecFfiLibraryPath.get())
    }
}

tasks.withType<Javadoc>().configureEach {
    val standardOptions = options as StandardJavadocDocletOptions
    standardOptions.addStringOption("Xdoclint:none", "-quiet")
}

tasks.named("processResources") {
    dependsOn(stageHostNativeResource)
    dependsOn(writeHostNativeManifest)
}

tasks.named<Jar>("sourcesJar") {
    // The runtime JAR intentionally carries native resources for JVM consumers,
    // but the source artifact must stay source-only for Maven Central hygiene.
    exclude("me/really/crypto/native/**")
}

val verifyBundledNativeResources = tasks.register("verifyBundledNativeResources") {
    group = "verification"
    description = "Verifies that release JVM artifacts include every supported native FFI library."
    dependsOn(stageHostNativeResource)
    dependsOn(writeHostNativeManifest)
    inputs.dir(nativeResourcesDir)
    doLast {
        if (!hostNativeSupported && !configuredNativeResourcesDir.isPresent) {
            throw GradleException("unsupported host platform for ReallyMe crypto JNI resources")
        }
        val root = nativeResourcesDir.get()
        verifyExactNativeResources(root, requiredNativeResources.toSet())
    }
}

val verifyHostBundledNativeResource = tasks.register("verifyHostBundledNativeResource") {
    group = "verification"
    description = "Verifies that local JVM artifacts include the host Rust JNI library."
    dependsOn(stageHostNativeResource)
    dependsOn(writeHostNativeManifest)
    inputs.dir(nativeResourcesDir)
    doLast {
        val hostResource = requiredHostNativeResource
            ?: throw GradleException("unsupported host platform for ReallyMe crypto JNI resources")
        val root = nativeResourcesDir.get()
        val expectedResources = if (requireFullNativeResources.get()) {
            requiredNativeResources.toSet()
        } else {
            setOf(hostResource, "me/really/crypto/native/native-manifest.json")
        }
        verifyExactNativeResources(
            root,
            expectedResources,
        )
    }
}

tasks.withType<PublishToMavenLocal>().configureEach {
    dependsOn(verifyHostBundledNativeResource)
    if (requireFullNativeResources.get()) {
        dependsOn(verifyBundledNativeResources)
    }
}

tasks.withType<PublishToMavenRepository>().configureEach {
    dependsOn(verifyBundledNativeResources)
}

val verifyRemoteMavenPublishingConfigured = tasks.register("verifyRemoteMavenPublishingConfigured") {
    group = "verification"
    description = "Verifies that every requested remote Maven publication is authenticated and signed."
    // A configured remote URL is itself authorization to create remote publish
    // tasks. Never let omission of the CI-only requireRemote flag bypass the
    // signing and credential gate for those tasks.
    onlyIf { requireRemoteMavenPublishing.get() || remoteMavenRepositoryUrlValue != null }
    doLast {
        val missing = buildList {
            if (remoteMavenRepositoryUrlValue == null) {
                add("REALLYME_MAVEN_REPOSITORY_URL or -Preallyme.maven.repositoryUrl")
            }
            if (remoteMavenUsernameValue == null) {
                add("REALLYME_MAVEN_USERNAME or -Preallyme.maven.username")
            }
            if (remoteMavenPasswordValue == null) {
                add("REALLYME_MAVEN_PASSWORD or -Preallyme.maven.password")
            }
            if (signingKeyValue == null) {
                add("MAVEN_SIGNING_KEY or -PsigningInMemoryKey")
            }
            if (signingPasswordValue == null) {
                add("MAVEN_SIGNING_PASSWORD or -PsigningInMemoryKeyPassword")
            }
        }
        if (missing.isNotEmpty()) {
            throw GradleException(
                "remote Maven publishing is not configured; missing non-empty ${missing.joinToString(", ")}"
            )
        }
    }
}

tasks.named("publish") {
    dependsOn(verifyRemoteMavenPublishingConfigured)
}

tasks.withType<PublishToMavenRepository>().configureEach {
    dependsOn(verifyRemoteMavenPublishingConfigured)
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "crypto"
            from(components["java"])
            pom {
                name.set("ReallyMe Crypto")
                description.set(
                    "Cross-platform cryptography facade for Kotlin, JVM, and Android."
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
        if (remoteMavenRepositoryUrlValue != null) {
            maven {
                name = "remoteRelease"
                url = uri(remoteMavenRepositoryUrlValue)
                credentials {
                    username = remoteMavenUsernameValue
                    password = remoteMavenPasswordValue
                }
            }
        }
    }
}

signing {
    if (signingKeyValue != null) {
        useInMemoryPgpKeys(signingKeyValue, signingPasswordValue)
        sign(publishing.publications["maven"])
    }
}
