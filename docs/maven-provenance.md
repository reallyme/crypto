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
| `me.really:codec:0.2.0` | `https://repo.maven.apache.org/maven2/me/really/codec/0.2.0/codec-0.2.0.jar` | `d05881f156df4b84a1d08ae074c9bd64a179d405b015f4d676fc8e8d9921b65f` | `reallyme/codec` tag `v0.2.0`, commit `142c9175ab012f8f715bbf5972117ea2cd867524` |
| `me.really:codec-android:0.2.0` | `https://repo.maven.apache.org/maven2/me/really/codec-android/0.2.0/codec-android-0.2.0.aar` | `0cbd62443dc06a775b378c86556c29f87f5e4a6da05575903300cb66e174cba0` | `reallyme/codec` tag `v0.2.0`, commit `142c9175ab012f8f715bbf5972117ea2cd867524` |

The published POMs identify ReallyMe LLC as the developer and
`https://github.com/reallyme/codec.git` as the SCM repository. The repository's
reviewed `v0.2.0` tag resolves to the commit recorded above. The artifact hashes
match the entries in `packages/kotlin/gradle/verification-metadata.xml` and
`packages/kotlin-android/gradle/verification-metadata.xml`, so strict Gradle
verification accepts only those reviewed registry bytes.

This evidence proves coordinate ownership through the published ReallyMe
namespace metadata, the reviewed source tag, and exact registry artifact
identity. It does not claim a reproducible byte-for-byte rebuild of the JAR or
AAR from source; that would require a separately documented reproducible-build
procedure.
