// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.publish.maven.tasks.PublishToMavenLocal
import org.gradle.api.publish.maven.tasks.PublishToMavenRepository
import org.gradle.api.publish.tasks.GenerateModuleMetadata
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

plugins {
    id("com.android.library") version "8.13.0"
    kotlin("android") version "2.4.0"
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
val jniLibsDir = providers.gradleProperty("reallyme.crypto.androidJniLibsDir")
    .map { file(it) }
    .orElse(layout.projectDirectory.dir("src/main/jniLibs").asFile)
val configuredNativeAssetsDir = providers.gradleProperty("reallyme.crypto.androidNativeAssetsDir")
val nativeAssetsDir = configuredNativeAssetsDir
    .map { file(it) }
    .orElse(layout.buildDirectory.dir("generated/android-native-assets").map { it.asFile })
val requireJniLibs = providers.gradleProperty("reallyme.crypto.requireAndroidJniLibs")
    .map { it == "true" }
    .orElse(false)

fun nonBlank(value: String?): String? = value?.trim()?.takeIf { it.isNotEmpty() }

val remoteMavenRepositoryUrlValue = nonBlank(remoteMavenRepositoryUrl.orNull)
val remoteMavenUsernameValue = nonBlank(remoteMavenUsername.orNull)
val remoteMavenPasswordValue = nonBlank(remoteMavenPassword.orNull)
val signingKeyValue = nonBlank(signingKey.orNull)
val signingPasswordValue = nonBlank(signingPassword.orNull)
val requiredAndroidJniLibs = listOf(
    "arm64-v8a/libcrypto_ffi.so",
    "armeabi-v7a/libcrypto_ffi.so",
    "x86_64/libcrypto_ffi.so",
    "x86/libcrypto_ffi.so",
)
val androidJniLib64BitLoadAlignments = mapOf(
    "arm64-v8a/libcrypto_ffi.so" to 16_384L,
    "x86_64/libcrypto_ffi.so" to 16_384L,
)
val androidJniLib32BitAlignmentPolicy = mapOf(
    "armeabi-v7a/libcrypto_ffi.so" to "presence-and-manifest",
    "x86/libcrypto_ffi.so" to "presence-and-manifest",
)
val requiredAndroidNativeManifest = "reallyme-crypto/native-manifest.json"
val androidNdkVersion = "29.0.14206865"

fun sha256Hex(bytes: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
    return digest.joinToString(separator = "") { byte -> "%02x".format(byte) }
}

fun checkedOutCommitSha(): String {
    val checkedOutSha = providers.exec {
        workingDir = layout.projectDirectory.dir("../..").asFile
        commandLine("git", "rev-parse", "HEAD")
    }.standardOutput.asText.get().trim()
    val fullSha = Regex("^[0-9a-f]{40}$")
    if (!fullSha.matches(checkedOutSha)) {
        throw GradleException("checked-out git commit SHA is not a lowercase full SHA")
    }
    val githubSha = providers.environmentVariable("GITHUB_SHA").orNull
    if (githubSha != null) {
        if (!fullSha.matches(githubSha)) {
            throw GradleException("GITHUB_SHA is not a lowercase full SHA")
        }
        if (githubSha != checkedOutSha) {
            throw GradleException("GITHUB_SHA does not match the checked-out source SHA")
        }
    }
    return checkedOutSha
}

fun verifyAndroidNativeManifest(
    manifestText: String,
    nativeBytes: Map<String, ByteArray>,
) {
    val parsed = try {
        JsonSlurper().parseText(manifestText)
    } catch (_: RuntimeException) {
        throw GradleException("Android native manifest is not valid JSON")
    }
    val root = parsed as? Map<*, *>
        ?: throw GradleException("Android native manifest root is not an object")
    if ((root["schemaVersion"] as? Number)?.toInt() != 1) {
        throw GradleException("Android native manifest schema version is invalid")
    }
    if (root["package"] != "reallyme-crypto-native") {
        throw GradleException("Android native manifest package is invalid")
    }
    if (root["commitSha"] != checkedOutCommitSha()) {
        throw GradleException("Android native manifest commit does not match the checked-out source")
    }
    val entries = root["entries"] as? List<*>
        ?: throw GradleException("Android native manifest entries are invalid")
    if (entries.size != nativeBytes.size) {
        throw GradleException("Android native manifest entry count is invalid")
    }

    val seenPaths = mutableSetOf<String>()
    for (entryValue in entries) {
        val entry = entryValue as? Map<*, *>
            ?: throw GradleException("Android native manifest entry is not an object")
        val relativePath = entry["path"] as? String
            ?: throw GradleException("Android native manifest entry path is invalid")
        if (!seenPaths.add(relativePath)) {
            throw GradleException("Android native manifest contains a duplicate path")
        }
        val bytes = nativeBytes[relativePath]
            ?: throw GradleException("Android native manifest contains an unexpected path")
        val expectedSize = (entry["size"] as? Number)?.toLong()
            ?: throw GradleException("Android native manifest entry size is invalid")
        val expectedDigest = entry["sha256"] as? String
            ?: throw GradleException("Android native manifest entry digest is invalid")
        if (expectedSize != bytes.size.toLong() || expectedDigest != sha256Hex(bytes)) {
            throw GradleException("Android native manifest does not match packaged JNI bytes")
        }
    }
    if (seenPaths != nativeBytes.keys) {
        throw GradleException("Android native manifest does not cover every required JNI path")
    }
}

fun readElfLittleEndian(bytes: ByteArray, offset: Int, byteCount: Int): Long {
    if (offset < 0 || byteCount < 0 || offset > bytes.size - byteCount) {
        throw GradleException("invalid ELF header offset")
    }
    var value = 0L
    for (index in 0 until byteCount) {
        value = value or ((bytes[offset + index].toLong() and 0xffL) shl (8 * index))
    }
    return value
}

fun verifyElf64LoadAlignment(file: File, relativePath: String, requiredAlignment: Long) {
    val bytes = file.readBytes()
    if (
        bytes.size < 64 ||
        bytes[0] != 0x7f.toByte() ||
        bytes[1] != 'E'.code.toByte() ||
        bytes[2] != 'L'.code.toByte() ||
        bytes[3] != 'F'.code.toByte()
    ) {
        throw GradleException("Android JNI library is not an ELF file: $relativePath")
    }
    if (bytes[4] != 2.toByte()) {
        throw GradleException("Android JNI library is not ELF64: $relativePath")
    }
    if (bytes[5] != 1.toByte()) {
        throw GradleException("Android JNI library is not little-endian ELF: $relativePath")
    }

    val programHeaderOffset = readElfLittleEndian(bytes, 32, 8)
    val programHeaderEntrySize = readElfLittleEndian(bytes, 54, 2)
    val programHeaderCount = readElfLittleEndian(bytes, 56, 2)
    if (programHeaderEntrySize < 56 || programHeaderCount == 0L) {
        throw GradleException("Android JNI library has no usable ELF program headers: $relativePath")
    }

    var sawLoadSegment = false
    for (index in 0L until programHeaderCount) {
        val headerOffset = programHeaderOffset + (index * programHeaderEntrySize)
        if (headerOffset < 0 || headerOffset > bytes.size.toLong() - programHeaderEntrySize) {
            throw GradleException("Android JNI library has truncated ELF program headers: $relativePath")
        }
        val headerOffsetInt = headerOffset.toInt()
        val programHeaderType = readElfLittleEndian(bytes, headerOffsetInt, 4)
        if (programHeaderType == 1L) {
            sawLoadSegment = true
            val loadAlignment = readElfLittleEndian(bytes, headerOffsetInt + 48, 8)
            if (loadAlignment < requiredAlignment || loadAlignment % requiredAlignment != 0L) {
                throw GradleException(
                    "Android JNI library $relativePath has LOAD alignment $loadAlignment; " +
                        "expected a multiple of $requiredAlignment"
                )
            }
        }
    }
    if (!sawLoadSegment) {
        throw GradleException("Android JNI library has no ELF LOAD segments: $relativePath")
    }
}

@Suppress("UNCHECKED_CAST")
fun patchAndroidModuleCapabilities(metadataFile: File) {
    // AGP publication variants do not inherit outgoing configuration capabilities,
    // so patch the generated module metadata that Gradle consumers actually read.
    val parsed = JsonSlurper().parse(metadataFile) as? MutableMap<String, Any?>
        ?: throw GradleException("invalid Android Gradle module metadata: root is not an object")
    val variants = parsed["variants"] as? List<Any?>
        ?: throw GradleException("invalid Android Gradle module metadata: variants are missing")
    val sharedCapability = listOf(
        mapOf(
            "group" to project.group.toString(),
            "name" to "crypto-android",
            "version" to project.version.toString(),
        ),
        mapOf(
            "group" to project.group.toString(),
            "name" to "crypto",
            "version" to project.version.toString(),
        )
    )
    var patchedApi = false
    var patchedRuntime = false
    for (variantValue in variants) {
        val variant = variantValue as? MutableMap<String, Any?>
            ?: throw GradleException("invalid Android Gradle module metadata: variant is not an object")
        when (variant["name"]) {
            "releaseVariantReleaseApiPublication" -> {
                variant["capabilities"] = sharedCapability
                patchedApi = true
            }
            "releaseVariantReleaseRuntimePublication" -> {
                variant["capabilities"] = sharedCapability
                patchedRuntime = true
            }
        }
    }
    if (!patchedApi || !patchedRuntime) {
        throw GradleException("Android Gradle module metadata is missing release API/runtime variants")
    }
    metadataFile.writeText(JsonOutput.prettyPrint(JsonOutput.toJson(parsed)) + "\n")
}

android {
    namespace = "me.really.crypto"
    compileSdk = 36
    ndkVersion = androidNdkVersion

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        aarMetadata {
            minCompileSdk = 36
        }
    }

    sourceSets {
        named("main") {
            manifest.srcFile("src/main/AndroidManifest.xml")
            java.srcDirs(
                "../kotlin/src/main/kotlin",
                "../../gen/java",
                "../../gen/kotlin",
            )
            // An explicit release resource directory is authoritative. Adding
            // it to AGP's default src/main/jniLibs directory makes repeatable
            // local and CI builds fail with duplicate native resources.
            jniLibs.setSrcDirs(listOf(jniLibsDir.get()))
            assets.srcDir(nativeAssetsDir.get().path)
        }
    }

    packaging {
        jniLibs {
            // The Rust build strips each staged library before its checksum is
            // recorded. AGP must preserve those attested bytes in the AAR.
            keepDebugSymbols.add("**/libcrypto_ffi.so")
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation("com.google.code.gson:gson:2.11.0")
    api("com.google.protobuf:protobuf-javalite:4.35.1")
    api("com.google.protobuf:protobuf-kotlin-lite:4.35.1")
    implementation("org.bouncycastle:bcprov-jdk18on:1.84")
    implementation("fr.acinq.secp256k1:secp256k1-kmp:0.23.0")
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.23.0")
    implementation("me.really:codec-android:0.2.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}

val buildAndroidJniLibs = tasks.register<Exec>("buildAndroidJniLibs") {
    onlyIf { !providers.gradleProperty("reallyme.crypto.androidJniLibsDir").isPresent }
    workingDir = layout.projectDirectory.asFile
    commandLine("scripts/build-jni-libs.sh")
}

val generateAndroidNativeManifest = tasks.register("generateAndroidNativeManifest") {
    group = "build"
    description = "Generates the Android native checksum manifest for local AAR builds."
    onlyIf { !configuredNativeAssetsDir.isPresent }
    dependsOn(buildAndroidJniLibs)
    inputs.dir(jniLibsDir)
    outputs.file(nativeAssetsDir.map { it.resolve(requiredAndroidNativeManifest) })
    doLast {
        val root = jniLibsDir.get()
        val nativeFiles = requiredAndroidJniLibs.map { relativePath ->
            val file = root.resolve(relativePath)
            if (!file.isFile) {
                throw GradleException("missing ReallyMe crypto Android jniLib for manifest: $relativePath")
            }
            file
        }
        val commitSha = checkedOutCommitSha()
        val entries = nativeFiles.map { file ->
            val relativePath = root.toPath().relativize(file.toPath()).toString().replace(File.separatorChar, '/')
            val bytes = file.readBytes()
            """{"path":"$relativePath","sha256":"${sha256Hex(bytes)}","size":${bytes.size}}"""
        }.joinToString(",")
        val manifest = """
            {"schemaVersion":1,"package":"reallyme-crypto-native","commitSha":"$commitSha","entries":[$entries]}
        """.trimIndent() + "\n"
        val manifestFile = nativeAssetsDir.get().resolve(requiredAndroidNativeManifest)
        manifestFile.parentFile.mkdirs()
        manifestFile.writeText(manifest)
    }
}

val verifyAndroidJniLibs = tasks.register("verifyAndroidJniLibs") {
    group = "verification"
    description = "Verifies that release Android AARs include every supported Rust JNI library."
    dependsOn(generateAndroidNativeManifest)
    inputs.dir(jniLibsDir).optional()
    inputs.dir(nativeAssetsDir).optional()
    onlyIf { requireJniLibs.get() }
    doLast {
        val root = jniLibsDir.get()
        val assetsRoot = nativeAssetsDir.get()
        val missing = requiredAndroidJniLibs.filter { relativePath ->
            !root.resolve(relativePath).isFile
        }
        if (missing.isNotEmpty()) {
            throw GradleException(
                "missing ReallyMe crypto Android jniLibs: ${missing.joinToString(", ")}"
            )
        }
        if (!assetsRoot.resolve(requiredAndroidNativeManifest).isFile) {
            throw GradleException(
                "missing ReallyMe crypto Android native manifest: $requiredAndroidNativeManifest"
            )
        }
        val nativeBytes = requiredAndroidJniLibs.associateWith { relativePath ->
            root.resolve(relativePath).readBytes()
        }
        try {
            verifyAndroidNativeManifest(
                assetsRoot.resolve(requiredAndroidNativeManifest).readText(),
                nativeBytes,
            )
        } finally {
            nativeBytes.values.forEach { bytes -> bytes.fill(0) }
        }
        androidJniLib64BitLoadAlignments.forEach { (relativePath, requiredAlignment) ->
            verifyElf64LoadAlignment(root.resolve(relativePath), relativePath, requiredAlignment)
        }
        androidJniLib32BitAlignmentPolicy.keys.forEach { relativePath ->
            if (!requiredAndroidJniLibs.contains(relativePath)) {
                throw GradleException("untracked Android 32-bit JNI library policy: $relativePath")
            }
        }
    }
}

tasks.named("preBuild") {
    dependsOn(buildAndroidJniLibs, generateAndroidNativeManifest, verifyAndroidJniLibs)
}

tasks.register("verifyReleaseAarContainsJniLibs") {
    group = "verification"
    description = "Verifies that the release AAR contains the expected jniLibs entries."
    dependsOn(generateAndroidNativeManifest, verifyAndroidJniLibs, "bundleReleaseAar")
    doLast {
        val aarFiles = layout.buildDirectory.dir("outputs/aar").get().asFile
            .listFiles { file -> file.isFile && file.name.endsWith("-release.aar") }
            ?.toList()
            .orEmpty()
        if (aarFiles.size != 1) {
            throw GradleException(
                "expected exactly one release AAR, found ${aarFiles.size}"
            )
        }
        ZipFile(aarFiles.single()).use { archive ->
            val manifestEntry = archive.getEntry("assets/$requiredAndroidNativeManifest")
                ?: throw GradleException(
                    "release AAR is missing native manifest asset: $requiredAndroidNativeManifest"
                )
            val packagedJniPaths = archive.entries().asSequence()
                .filter { entry ->
                    !entry.isDirectory && entry.name.startsWith("jni/") && entry.name.endsWith(".so")
                }
                .map { entry -> entry.name.removePrefix("jni/") }
                .toSet()
            if (packagedJniPaths != requiredAndroidJniLibs.toSet()) {
                throw GradleException("release AAR JNI entry set does not match the approved ABI set")
            }
            val manifestText = archive.getInputStream(manifestEntry)
                .bufferedReader()
                .use { reader -> reader.readText() }
            val nativeBytes = requiredAndroidJniLibs.associateWith { relativePath ->
                val entry = archive.getEntry("jni/$relativePath")
                    ?: throw GradleException("release AAR is missing a required JNI entry")
                archive.getInputStream(entry).use { input -> input.readBytes() }
            }
            try {
                verifyAndroidNativeManifest(manifestText, nativeBytes)
            } finally {
                nativeBytes.values.forEach { bytes -> bytes.fill(0) }
            }
        }
    }
}

tasks.withType<PublishToMavenLocal>().configureEach {
    dependsOn("verifyReleaseAarContainsJniLibs")
}

tasks.withType<PublishToMavenRepository>().configureEach {
    dependsOn("verifyReleaseAarContainsJniLibs")
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

tasks.withType<GenerateModuleMetadata>().configureEach {
    if (name == "generateMetadataFileForAndroidReleasePublication") {
        doLast {
            patchAndroidModuleCapabilities(
                layout.buildDirectory.file("publications/androidRelease/module.json").get().asFile
            )
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("androidRelease") {
                artifactId = "crypto-android"
                from(components["release"])
                pom {
                    name.set("ReallyMe Crypto Android")
                    description.set(
                        "Android AAR for the ReallyMe cryptography facade."
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
            sign(publishing.publications["androidRelease"])
        }
    }
}
