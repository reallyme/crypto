// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.publish.maven.tasks.PublishToMavenLocal
import org.gradle.api.publish.maven.tasks.PublishToMavenRepository
import org.gradle.api.publish.tasks.GenerateModuleMetadata
import org.gradle.external.javadoc.StandardJavadocDocletOptions
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.security.MessageDigest

plugins {
    id("com.android.library") version "8.13.0"
    kotlin("android") version "2.4.0"
    `maven-publish`
    signing
}

group = "me.really"
version = "0.2.0"

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
val requiredAndroidNativeManifest = "reallyme-crypto/native-manifest.json"

fun sha256Hex(bytes: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
    return digest.joinToString(separator = "") { byte -> "%02x".format(byte) }
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

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    api("com.google.protobuf:protobuf-javalite:4.35.1")
    api("com.google.protobuf:protobuf-kotlin-lite:4.35.1")
    implementation("org.bouncycastle:bcprov-jdk18on:1.84")
    implementation("fr.acinq.secp256k1:secp256k1-kmp:0.23.0")
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.23.0")
    implementation("me.really:codec-android:0.1.21")
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
        val commitSha = providers.environmentVariable("GITHUB_SHA").orNull
            ?: providers.exec {
                workingDir = layout.projectDirectory.dir("../..").asFile
                commandLine("git", "rev-parse", "HEAD")
            }.standardOutput.asText.get().trim()
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
    }
}

tasks.named("preBuild") {
    dependsOn(buildAndroidJniLibs, generateAndroidNativeManifest, verifyAndroidJniLibs)
}

tasks.register("verifyReleaseAarContainsJniLibs") {
    group = "verification"
    description = "Verifies that the release AAR contains the expected jniLibs entries."
    dependsOn(generateAndroidNativeManifest, "bundleReleaseAar")
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
        val aarFile = aarFiles.single()
        val missing = requiredAndroidJniLibs.filter { relativePath ->
            !zipTree(aarFile).matching {
                include("jni/$relativePath")
            }.files.any()
        }
        if (missing.isNotEmpty()) {
            throw GradleException(
                "release AAR is missing JNI entries: ${missing.joinToString(", ")}"
            )
        }
        val hasNativeManifest = zipTree(aarFile).matching {
            include("assets/$requiredAndroidNativeManifest")
        }.files.any()
        if (!hasNativeManifest) {
            throw GradleException(
                "release AAR is missing native manifest asset: $requiredAndroidNativeManifest"
            )
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
    description = "Verifies that remote Maven publishing credentials are configured."
    onlyIf { requireRemoteMavenPublishing.get() }
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

tasks.withType<Javadoc>().configureEach {
    val standardOptions = options as StandardJavadocDocletOptions
    standardOptions.addStringOption("Xdoclint:none", "-quiet")
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
                        "Android AAR for the ReallyMe cryptography compatibility facade."
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
