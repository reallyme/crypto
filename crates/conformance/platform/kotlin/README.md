# Kotlin vector conformance

This JVM harness checks shared vectors against JCA/JCE and BouncyCastle.
The SDK is in [`packages/kotlin`](../../../../packages/kotlin).

```sh
cd crates/conformance/platform/kotlin
./gradlew test --rerun-tasks
```

`--rerun-tasks` forces execution instead of an up-to-date result. Set
`REALLYME_CRYPTO_VECTORS_DIR` to use a different vector directory.
Review dependency changes before updating `gradle/verification-metadata.xml`.
