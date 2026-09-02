<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Maven Artifact Provenance

This record binds the JVM and Android codec dependencies used by ReallyMe
Crypto to reviewed Maven Central bytes and to the ReallyMe codec source release.
It is release evidence for the `me.really` namespace; changing a coordinate,
version, checksum, or source release requires a new review of this record and
the corresponding Gradle verification metadata.

| Coordinate | Maven Central artifact | SHA-256 | Reviewed source release |
| --- | --- | --- | --- |
| `me.really:codec:0.2.1` | `https://repo.maven.apache.org/maven2/me/really/codec/0.2.1/codec-0.2.1.jar` | `485ce03b61be0eca66f3c481392b6b4b234c47a306af356e342e627007c536e0` | `reallyme/codec` tag `v0.2.1`, commit `c584eef1e7fa829ac9c845bffb5fadb19fa1b9e3` |
| `me.really:codec-android:0.2.1` | `https://repo.maven.apache.org/maven2/me/really/codec-android/0.2.1/codec-android-0.2.1.aar` | `dafac20329ab1e5e0b9805f3acb8727bc5e08ff93222a146762f76ab4fbd4dc6` | `reallyme/codec` tag `v0.2.1`, commit `c584eef1e7fa829ac9c845bffb5fadb19fa1b9e3` |

The published POMs identify ReallyMe LLC as the developer and
`https://github.com/reallyme/codec.git` as the SCM repository. The repository's
reviewed `v0.2.1` tag resolves to the commit recorded above. The artifact hashes
match the entries in `packages/kotlin/gradle/verification-metadata.xml` and
`packages/kotlin-android/gradle/verification-metadata.xml`, so strict Gradle
verification accepts only those reviewed registry bytes.

This evidence proves coordinate ownership through the published ReallyMe
namespace metadata, the reviewed source tag, and exact registry artifact
identity. It does not claim a reproducible byte-for-byte rebuild of the JAR or
AAR from source; that would require a separately documented reproducible-build
procedure.
