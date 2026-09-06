<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
-->

# Maven Artifact Provenance

This record binds the JVM and Android codec dependencies used by ReallyMe
Crypto to reviewed Maven Central bytes and to the ReallyMe codec source release.
It is release evidence for the `me.really` namespace; changing a coordinate,
version, checksum, or source release requires a new review of this record and
the corresponding Gradle verification metadata.

| Coordinate | Maven Central artifact | SHA-256 | Reviewed source release |
| --- | --- | --- | --- |
| `me.really:codec:0.2.3` | `https://repo.maven.apache.org/maven2/me/really/codec/0.2.3/codec-0.2.3.jar` | `a85f18da11b207f7a675d5cee19b295f090e647a5d0483517b036c32d89a73da` | `reallyme/codec` tag `v0.2.3`, commit `50e7053b683ef54155fa794d1a84a7db67a4ab57` |
| `me.really:codec-android:0.2.3` | `https://repo.maven.apache.org/maven2/me/really/codec-android/0.2.3/codec-android-0.2.3.aar` | `d71f6481d903e88fdf7a58def6ab3b81b15f4666f8acc7dcedbd02b5e523676a` | `reallyme/codec` tag `v0.2.3`, commit `50e7053b683ef54155fa794d1a84a7db67a4ab57` |

The published POMs identify ReallyMe LLC as the developer and
`https://github.com/reallyme/codec.git` as the SCM repository. The repository's
reviewed `v0.2.3` tag resolves to the commit recorded above. The artifact hashes
match the entries in `packages/kotlin/gradle/verification-metadata.xml` and
`packages/kotlin-android/gradle/verification-metadata.xml`, so strict Gradle
verification accepts only those reviewed registry bytes.

This evidence proves coordinate ownership through the published ReallyMe
namespace metadata, the reviewed source tag, and exact registry artifact
identity. It does not claim a reproducible byte-for-byte rebuild of the JAR or
AAR from source; that would require a separately documented reproducible-build
procedure.
