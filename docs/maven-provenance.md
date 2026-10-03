# Maven Artifact Provenance

This record binds the JVM and Android codec dependencies used by ReallyMe
Crypto to reviewed Maven Central bytes and to the ReallyMe codec source release.
It is release evidence for the `me.really` namespace; changing a coordinate,
version, checksum, or source release requires a new review of this record and
the corresponding Gradle verification metadata.

| Coordinate | Maven Central artifact | SHA-256 | Reviewed source release |
| --- | --- | --- | --- |
| `me.really:codec:0.3.1` | `https://repo.maven.apache.org/maven2/me/really/codec/0.3.1/codec-0.3.1.jar` | `976826b466f0f5668ec1dc7db9672607bb2d466d010832e61218e9d5bdfacc4e` | `reallyme/codec` tag `v0.3.1`, commit `a3d61910e69398a199ca11305ca555a28f4fa09b` |
| `me.really:codec-android:0.3.1` | `https://repo.maven.apache.org/maven2/me/really/codec-android/0.3.1/codec-android-0.3.1.aar` | `25d3d6e964acd323e12cdaee1680cfe5534fec77671fddf62776e4bfc8520190` | `reallyme/codec` tag `v0.3.1`, commit `a3d61910e69398a199ca11305ca555a28f4fa09b` |

The published POMs identify ReallyMe LLC as the developer and
`https://github.com/reallyme/codec.git` as the SCM repository. The repository's
reviewed `v0.3.1` tag resolves to the commit recorded above. The artifact hashes
match the entries in `packages/kotlin/gradle/verification-metadata.xml` and
`packages/kotlin-android/gradle/verification-metadata.xml`, so strict Gradle
verification accepts only those reviewed registry bytes.

This evidence proves coordinate ownership through the published ReallyMe
namespace metadata, the reviewed source tag, and exact registry artifact
identity. It does not claim a reproducible byte-for-byte rebuild of the JAR or
AAR from source; that would require a separately documented reproducible-build
procedure.
