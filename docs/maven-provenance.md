# Verifying Maven dependencies

Gradle uses strict checksum verification. The artifact bytes accepted by each
build are recorded in that build's `gradle/verification-metadata.xml`.
Provenance inputs and checked artifact hashes are validated by:

```sh
python3 scripts/gradle_runtime_lockfiles.py --check
python3 scripts/verify_gradle_checksum_provenance.py
```

When updating a dependency, review its coordinate, source and downloaded bytes
before changing verification metadata. Do not accept a new hash solely to make
a build pass. JVM and Android have separate metadata and must both be updated
when a shared dependency changes.

The source currently requires Codec 0.4.4; existing lockfiles and verification
records have not yet advanced to that release. Resolve that mismatch before
publication. The checksums establish accepted artifact identity, not a
reproducible source-to-binary build.
