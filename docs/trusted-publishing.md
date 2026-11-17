# Trusted publishing

The npm and crates.io release workflows authenticate through GitHub Actions
OIDC. They publish only the checksum-verified artifacts selected by the release
verification job. Persistent registry publish tokens are not workflow inputs.
The crates.io authentication action returns a temporary token and revokes it
when the job finishes. npm authenticates directly through its OIDC integration.

Configure these publisher identities in the registry accounts before using the
workflows:

| Registry/package | GitHub owner/repository | Workflow filename | Required environment |
| --- | --- | --- | --- |
| npm `@reallyme/crypto` | `reallyme/crypto` | `npm-package-release.yml` | `npm-release` |
| Every published workspace crate | `reallyme/crypto` | `crates-release.yml` | `crates-io-release` |

Use the exact environment names in both registry configurations. Restrict each
GitHub release environment to the `main` branch and keep its deployment
protection rules enabled. `id-token: write` belongs only to the environment-bound
publish jobs; preflight and source-verification jobs do not need it.

For npm, allow direct publication by the configured trusted publisher. The
workflow uses a compatible Node/npm toolchain, the public npm registry, and no
token-bearing user configuration. For crates.io, configure every crate in the
dependency publication order, including prerequisites; configuring only the root
crate cannot authorize publication of its dependencies.

After publisher identities and environment protections are active, remove
repository- or organization-scoped `NPM_TOKEN` and `CARGO_REGISTRY_TOKEN`
publishing secrets and revoke their underlying registry tokens. Do this during
the workflow cutover, so the previously deployed token-based workflow cannot
be selected for a later release. Trusted publishing requires no replacement
publish tokens in environment secrets. Other release credentials, if needed,
must remain scoped to the corresponding release environment.

Account-side publisher registration, environment protections, and token
revocation are deployment prerequisites. A passing source-policy check does not
establish that these external settings are configured. An absent or mismatched
publisher identity causes publication to fail without a stored-token fallback.

See the [npm trusted publishing documentation](https://docs.npmjs.com/trusted-publishers/)
and the [official crates.io authentication action](https://github.com/rust-lang/crates-io-auth-action)
for registry configuration and temporary-token handling.
