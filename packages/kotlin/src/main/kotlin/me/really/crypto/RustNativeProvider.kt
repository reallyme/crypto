// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.Locale

/**
 * Explicit loader for the ReallyMe Rust native provider.
 *
 * Rust-backed Kotlin primitives do not silently fall back to pure Kotlin or
 * platform providers. Applications load the audited `crypto-ffi` native library
 * once, then provider-aware algorithms such as Argon2id can call their JNI
 * entry points.
 */
public object ReallyMeRustNativeProvider {
    private const val RESOURCE_ROOT: String = "/me/really/crypto/native"
    private const val RESOURCE_MANIFEST_PATH: String = "$RESOURCE_ROOT/native-manifest.json"
    private const val BUNDLED_LIBRARY_NAME: String = "crypto_ffi"
    // Escape both JSON object delimiters explicitly. Android's ICU regex engine
    // rejects an unmatched literal closing brace even though the desktop JVM accepts it.
    private val nativeManifestEntryRegex = Regex(
        "\\{\\s*\"path\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*" +
            "\"sha256\"\\s*:\\s*\"([0-9a-f]{64})\"\\s*,\\s*" +
            "\"size\"\\s*:\\s*([0-9]+)\\s*\\}",
    )

    @Volatile
    private var loaded: Boolean = false
    private var loadedLibraryPath: String? = null

    /**
     * Loads `libcrypto_ffi.so` from platform-managed native-library locations.
     *
     * Android AAR consumers should use this method after dependency
     * initialization. It keeps native-provider activation explicit while letting
     * Android's package manager locate the library from `jniLibs/<abi>`.
     */
    @JvmStatic
    @Synchronized
    public fun loadBundledLibrary() {
        val status = loadBundledLibraryStatus()
        if (status != ReallyMeNativeStatus.OK) {
            throw status.toFacadeError()
        }
    }

    @JvmStatic
    @Synchronized
    public fun loadLibrary(path: String) {
        val status = loadLibraryStatus(path)
        if (status != ReallyMeNativeStatus.OK) {
            throw status.toFacadeError()
        }
    }

    @JvmStatic
    @Synchronized
    public fun loadBundledLibraryStatus(): ReallyMeNativeStatus {
        if (loaded) {
            return ReallyMeNativeStatus.OK
        }
        if (isAndroidRuntime()) {
            return loadAndroidLibraryStatus()
        }
        return loadClasspathResourceStatus()
    }

    private fun loadAndroidLibraryStatus(): ReallyMeNativeStatus {
        return try {
            System.loadLibrary(BUNDLED_LIBRARY_NAME)
            markLoadedAfterProbe(loadedPath = null)
        } catch (_: LinkageError) {
            ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        } catch (_: SecurityException) {
            ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        }
    }

    private fun loadClasspathResourceStatus(): ReallyMeNativeStatus {
        val resource = platformNativeResource() ?: return ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        val stream = ReallyMeRustNativeProvider::class.java.getResourceAsStream(resource.path)
            ?: return ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        val bytes = try {
            stream.use { source -> source.readBytes() }
        } catch (_: IOException) {
            return ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        } catch (_: SecurityException) {
            return ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        }
        if (!verifyNativeResource(resource, bytes)) {
            return ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        }
        val extracted = extractNativeResourceForLoad(resource, bytes)
        if (extracted == null) {
            return ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        }

        return loadExtractedLibraryStatus(resource, extracted)
    }

    internal fun extractNativeResourceForLoad(
        resource: NativeResource,
        bytes: ByteArray,
        parentDirectory: Path? = null,
    ): Path? {
        if (!verifyNativeResource(resource, bytes)) {
            return null
        }
        var extractionDirectory: Path? = null
        var target: Path? = null
        return try {
            extractionDirectory = if (parentDirectory == null) {
                Files.createTempDirectory("reallyme-crypto-native-")
            } else {
                Files.createTempDirectory(parentDirectory, "reallyme-crypto-native-")
            }
            if (!applyOwnerOnlyPermissions(extractionDirectory, OWNER_ONLY_DIRECTORY_PERMISSIONS)) {
                cleanupExtractedLibrary(target, extractionDirectory)
                return null
            }
            target = extractionDirectory.resolve(resource.fileName)
            FileChannel.open(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) {
                    channel.write(buffer)
                }
                channel.force(true)
            }
            if (!applyOwnerOnlyPermissions(target, OWNER_ONLY_FILE_PERMISSIONS)) {
                cleanupExtractedLibrary(target, extractionDirectory)
                return null
            }
            if (!verifyNativeResourceOnDisk(resource, target)) {
                cleanupExtractedLibrary(target, extractionDirectory)
                null
            } else {
                target.toFile().deleteOnExit()
                extractionDirectory.toFile().deleteOnExit()
                target
            }
        } catch (_: IOException) {
            cleanupExtractedLibrary(target, extractionDirectory)
            null
        } catch (_: SecurityException) {
            cleanupExtractedLibrary(target, extractionDirectory)
            null
        } catch (_: UnsupportedOperationException) {
            cleanupExtractedLibrary(target, extractionDirectory)
            null
        }
    }

    private fun verifyNativeResource(resource: NativeResource, bytes: ByteArray): Boolean {
        val entry = nativeManifestEntries().firstOrNull { it.path == resource.manifestPath }
            ?: return false
        if (entry.size != bytes.size) {
            return false
        }
        return try {
            sha256Hex(bytes) == entry.sha256
        } catch (_: NoSuchAlgorithmException) {
            false
        }
    }

    private fun nativeManifestEntries(): List<NativeManifestEntry> {
        val stream = ReallyMeRustNativeProvider::class.java.getResourceAsStream(RESOURCE_MANIFEST_PATH)
            ?: return emptyList()
        val text = try {
            stream.use { source -> source.reader(Charsets.UTF_8).readText() }
        } catch (_: IOException) {
            return emptyList()
        } catch (_: SecurityException) {
            return emptyList()
        }
        return nativeManifestEntryRegex.findAll(text).mapNotNull { match ->
            val size = match.groupValues[3].toIntOrNull() ?: return@mapNotNull null
            NativeManifestEntry(
                path = match.groupValues[1],
                sha256 = match.groupValues[2],
                size = size,
            )
        }.toList()
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return hexLower(digest)
    }

    internal fun verifyNativeResourceOnDisk(resource: NativeResource, path: Path): Boolean {
        val entry = nativeManifestEntries().firstOrNull { it.path == resource.manifestPath }
            ?: return false
        return try {
            if (Files.size(path) != entry.size.toLong()) {
                return false
            }
            sha256Hex(path) == entry.sha256
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        } catch (_: NoSuchAlgorithmException) {
            false
        }
    }

    private fun sha256Hex(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path).use { source ->
            val buffer = ByteArray(FILE_HASH_BUFFER_BYTES)
            var read = source.read(buffer)
            while (read >= 0) {
                digest.update(buffer, 0, read)
                read = source.read(buffer)
            }
        }
        return hexLower(digest.digest())
    }

    private fun hexLower(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (byte in bytes) {
            val value = byte.toInt() and 0xff
            out.append(HEX_DIGITS[value ushr 4])
            out.append(HEX_DIGITS[value and 0x0f])
        }
        return out.toString()
    }

    internal fun validateExtractedLibraryForLoad(resource: NativeResource, path: Path): Path? {
        return try {
            if (Files.isSymbolicLink(path)) {
                return null
            }
            val loadedPath = path.toRealPath()
            if (!Files.isRegularFile(loadedPath, LinkOption.NOFOLLOW_LINKS)) {
                return null
            }
            val loadedParent = loadedPath.parent ?: return null
            if (!hasExpectedOwnerOnlyPermissions(loadedParent, OWNER_ONLY_DIRECTORY_PERMISSIONS) ||
                !hasExpectedOwnerOnlyPermissions(loadedPath, OWNER_ONLY_FILE_PERMISSIONS) ||
                !verifyNativeResourceOnDisk(resource, loadedPath)
            ) {
                return null
            }
            loadedPath
        } catch (_: IOException) {
            null
        } catch (_: SecurityException) {
            null
        } catch (_: UnsupportedOperationException) {
            null
        }
    }

    private fun loadExtractedLibraryStatus(
        resource: NativeResource,
        path: Path,
    ): ReallyMeNativeStatus {
        return try {
            val loadedPath = validateExtractedLibraryForLoad(resource, path)
                ?: return ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
            // Keep the final on-disk digest and permission verification directly
            // adjacent to loading. Java cannot provide an fd-backed System.load,
            // so minimizing this interval is the strongest portable contract.
            System.load(loadedPath.toString())
            markLoadedAfterProbe(loadedPath.toString())
        } catch (_: LinkageError) {
            cleanupExtractedLibrary(path, path.parent)
            ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        } catch (_: SecurityException) {
            cleanupExtractedLibrary(path, path.parent)
            ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        } catch (_: IOException) {
            cleanupExtractedLibrary(path, path.parent)
            ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        }
    }

    private fun applyOwnerOnlyPermissions(
        path: Path,
        expected: Set<PosixFilePermission>,
    ): Boolean {
        val view = Files.getFileAttributeView(path, PosixFileAttributeView::class.java)
            ?: return true
        return try {
            view.setPermissions(expected)
            view.readAttributes().permissions() == expected
        } catch (_: UnsupportedOperationException) {
            false
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    private fun hasExpectedOwnerOnlyPermissions(
        path: Path,
        expected: Set<PosixFilePermission>,
    ): Boolean {
        val view = Files.getFileAttributeView(path, PosixFileAttributeView::class.java)
            ?: return true
        return try {
            view.readAttributes().permissions() == expected
        } catch (_: UnsupportedOperationException) {
            false
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    private fun cleanupExtractedLibrary(target: Path?, directory: Path?) {
        try {
            if (target != null) {
                Files.deleteIfExists(target)
            }
            if (directory != null) {
                Files.deleteIfExists(directory)
            }
        } catch (_: IOException) {
        } catch (_: SecurityException) {
        }
    }

    @JvmStatic
    @Synchronized
    public fun loadLibraryStatus(path: String): ReallyMeNativeStatus {
        if (path.isEmpty()) {
            return ReallyMeNativeStatus.INVALID_INPUT
        }
        val canonicalPath = try {
            val file = File(path)
            if (!file.isFile) {
                return ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
            }
            file.canonicalPath
        } catch (_: IOException) {
            return ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        } catch (_: SecurityException) {
            return ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        }
        if (loaded) {
            return if (loadedLibraryPath == canonicalPath) {
                ReallyMeNativeStatus.OK
            } else {
                ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
            }
        }
        return try {
            System.load(canonicalPath)
            markLoadedAfterProbe(canonicalPath)
        } catch (_: LinkageError) {
            ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        } catch (_: SecurityException) {
            ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        }
    }

    @Synchronized
    internal fun requireLoaded() {
        if (!loaded) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    private fun markLoadedAfterProbe(loadedPath: String?): ReallyMeNativeStatus {
        return if (probeNative() == 1) {
            loaded = true
            loadedLibraryPath = loadedPath
            ReallyMeNativeStatus.OK
        } else {
            ReallyMeNativeStatus.PROVIDER_UNAVAILABLE
        }
    }

    internal fun platformNativeResource(
        osName: String? = System.getProperty("os.name"),
        osArch: String? = System.getProperty("os.arch"),
        androidRuntime: Boolean = isAndroidRuntime(),
    ): NativeResource? {
        if (androidRuntime) {
            return null
        }
        val os = normalizedOs(osName) ?: return null
        val arch = normalizedArch(osArch) ?: return null
        val fileName = nativeLibraryFileName(os)
        return NativeResource(
            fileName = fileName,
            path = "$RESOURCE_ROOT/$os-$arch/$fileName",
            manifestPath = "$os-$arch/$fileName",
        )
    }

    internal fun normalizedOs(osName: String?): String? {
        val value = osName?.lowercase(Locale.ROOT) ?: return null
        return when {
            value.contains("mac") || value.contains("darwin") -> "macos"
            value.contains("linux") -> "linux"
            value.contains("windows") -> "windows"
            else -> null
        }
    }

    internal fun normalizedArch(osArch: String?): String? {
        return when (osArch?.lowercase(Locale.ROOT)) {
            "aarch64", "arm64" -> "aarch64"
            "amd64", "x86_64" -> "x86_64"
            else -> null
        }
    }

    internal fun isAndroidRuntime(
        runtimeName: String? = System.getProperty("java.runtime.name"),
        vmName: String? = System.getProperty("java.vm.name"),
        vmVendor: String? = System.getProperty("java.vm.vendor"),
    ): Boolean {
        return containsAndroidMarker(runtimeName) ||
            containsAndroidMarker(vmName) ||
            containsAndroidMarker(vmVendor)
    }

    private fun containsAndroidMarker(value: String?): Boolean {
        val normalized = value?.lowercase(Locale.ROOT) ?: return false
        return normalized.contains("android") || normalized.contains("dalvik")
    }

    private fun nativeLibraryFileName(os: String): String =
        when (os) {
            "macos" -> "libcrypto_ffi.dylib"
            "windows" -> "crypto_ffi.dll"
            else -> "libcrypto_ffi.so"
        }

    internal data class NativeResource(
        val fileName: String,
        val path: String,
        val manifestPath: String,
    )

    private data class NativeManifestEntry(
        val path: String,
        val sha256: String,
        val size: Int,
    )

    @JvmStatic
    private external fun probeNative(): Int

    private const val HEX_DIGITS: String = "0123456789abcdef"
    private const val FILE_HASH_BUFFER_BYTES: Int = 8192
    private val OWNER_ONLY_DIRECTORY_PERMISSIONS: Set<PosixFilePermission> = setOf(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
        PosixFilePermission.OWNER_EXECUTE,
    )
    private val OWNER_ONLY_FILE_PERMISSIONS: Set<PosixFilePermission> = setOf(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
    )
}
