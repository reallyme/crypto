# Maven Artifact Provenance

This record binds the JVM and Android codec dependencies used by ReallyMe
Crypto to reviewed Maven Central bytes and to the ReallyMe codec source release.
It is release evidence for the `me.really` namespace; changing a coordinate,
version, checksum, or source release requires a new review of this record and
the corresponding Gradle verification metadata.

| Coordinate | Maven Central artifact | SHA-256 | Reviewed source release |
| --- | --- | --- | --- |
| `me.really:codec:0.3.0` | `https://repo.maven.apache.org/maven2/me/really/codec/0.3.0/codec-0.3.0.jar` | `e2cdfb2c2e3081878567617656e89dcfffba840a9c7e94209bfbe859dfe50ac5` | `reallyme/codec` tag `v0.3.0`, commit `e0b5e100f81043d33afcdb9bc7a1bf5f8edab9ba` |
| `me.really:codec-android:0.3.0` | `https://repo.maven.apache.org/maven2/me/really/codec-android/0.3.0/codec-android-0.3.0.aar` | `a6b1d56312641f1db1299d96a46e17eb416386ede0f5732bcb9c027a1e7575ba` | `reallyme/codec` tag `v0.3.0`, commit `e0b5e100f81043d33afcdb9bc7a1bf5f8edab9ba` |

The published POMs identify ReallyMe LLC as the developer and
`https://github.com/reallyme/codec.git` as the SCM repository. The repository's
reviewed `v0.3.0` tag resolves to the commit recorded above. The artifact hashes
match the entries in `packages/kotlin/gradle/verification-metadata.xml` and
`packages/kotlin-android/gradle/verification-metadata.xml`, so strict Gradle
verification accepts only those reviewed registry bytes.

This evidence proves coordinate ownership through the published ReallyMe
namespace metadata, the reviewed source tag, and exact registry artifact
identity. It does not claim a reproducible byte-for-byte rebuild of the JAR or
AAR from source; that would require a separately documented reproducible-build
procedure.
