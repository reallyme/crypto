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
| `me.really:codec:0.4.1` | `https://repo.maven.apache.org/maven2/me/really/codec/0.4.1/codec-0.4.1.jar` | `aab5e5ddb778c2ac00e66bf530f55bfffa616afd7c64f2aea7b3ff00ea9dc77c` | `reallyme/codec` 0.4.1, reviewed 0.4.1 source `43fab3a269c65b7e0c72ebec4ab31c1b893f3fad` |
| `me.really:codec-android:0.4.1` | `https://repo.maven.apache.org/maven2/me/really/codec-android/0.4.1/codec-android-0.4.1.aar` | `eab0a81f6cf4ae340f702a82f296a9c057121cf8f73bf6caf41f89406f64f00c` | `reallyme/codec` 0.4.1, reviewed 0.4.1 source `43fab3a269c65b7e0c72ebec4ab31c1b893f3fad` |
| `me.really:codec:0.4.3` | `https://repo.maven.apache.org/maven2/me/really/codec/0.4.3/codec-0.4.3.jar` | `8230e722d93adaa90a9ed904fbd656fce7aee161bb76403dfdd1accb2d4fbe61` | `reallyme/codec` 0.4.3, release source `2f93ffdbfaa71a556b0d736e29936aee14ed634d` |
| `me.really:codec-android:0.4.3` | `https://repo.maven.apache.org/maven2/me/really/codec-android/0.4.3/codec-android-0.4.3.aar` | `58dc49b31e621a17996caecbba6e2eceaec572623d29dac3f4c25589d775b5e7` | `reallyme/codec` 0.4.3, release source `2f93ffdbfaa71a556b0d736e29936aee14ed634d` |

The published POMs identify ReallyMe Technologies Limited as the developer and
`https://github.com/reallyme/codec.git` as the SCM repository. The artifact hashes
match the entries in `packages/kotlin/gradle/verification-metadata.xml` and
`packages/kotlin-android/gradle/verification-metadata.xml`, so strict Gradle
verification accepts only those reviewed registry bytes.

This evidence proves coordinate ownership through the published ReallyMe
namespace metadata, the reviewed source, and exact registry artifact
identity. It does not claim a reproducible byte-for-byte rebuild of the JAR or
AAR from source; that would require a separately documented reproducible-build
procedure.
