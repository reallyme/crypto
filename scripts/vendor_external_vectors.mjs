// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// Vendors additional third-party conformance corpora (Wycheproof, BIP-340,
// RFC 8032) into vectors/external, records per-file SHA-256 provenance, and
// flips the corresponding coverage rows to a vendored source.
//
// Vendoring is a deliberate, reviewed act: each source's upstream commit must
// be pinned explicitly (via the *_REF environment variables below). The script
// refuses to run against an unpinned ref so a reviewer always chooses the exact
// bytes that become audit evidence. Requires network access; intended to run in
// the external-vectors audit workflow, not on the per-PR wall.
//
// Usage:
//   WYCHEPROOF_REF=<commit> BIP340_REF=<commit> RFC8032_REF=<commit> \
//     node scripts/vendor_external_vectors.mjs [source ...]
//
// With no positional args every source is vendored; otherwise only the named
// sources (wycheproof, bip340, rfc8032).

import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const EXTERNAL_DIR = join(REPO_ROOT, "vectors", "external");
const PROVENANCE_PATH = join(EXTERNAL_DIR, "provenance.json");
const RETRIEVED_AT = new Date().toISOString().slice(0, 10);

const SOURCES = {
  wycheproof: {
    source_id: "wycheproof",
    name: "Google/C2SP Wycheproof test vectors",
    website_url: "https://github.com/C2SP/wycheproof",
    repo: "C2SP/wycheproof",
    ref: process.env.WYCHEPROOF_REF,
    license: {
      declared: "Apache-2.0",
      note: "Wycheproof vectors are published under Apache-2.0; pinned by commit with per-file hashes.",
    },
    files: [
      {
        upstream: "testvectors_v1/chacha20_poly1305_test.json",
        local: "wycheproof/chacha20_poly1305_test.json",
        format: "json",
        coverage: "ChaCha20-Poly1305",
      },
      {
        upstream: "testvectors_v1/ecdsa_secp256k1_sha256_test.json",
        local: "wycheproof/ecdsa_secp256k1_sha256_test.json",
        format: "json",
        coverage: "secp256k1/BIP-340",
      },
      {
        // X25519 already has an ACVP coverage row; add the file and hash
        // without overwriting that row's source attribution.
        upstream: "testvectors_v1/x25519_test.json",
        local: "wycheproof/x25519_test.json",
        format: "json",
      },
      {
        upstream: "testvectors_v1/x448_test.json",
        local: "wycheproof/x448_test.json",
        format: "json",
      },
      {
        upstream: "testvectors_v1/ecdh_secp256r1_ecpoint_test.json",
        local: "wycheproof/ecdh_secp256r1_ecpoint_test.json",
        format: "json",
      },
      {
        upstream: "testvectors_v1/ecdh_secp384r1_ecpoint_test.json",
        local: "wycheproof/ecdh_secp384r1_ecpoint_test.json",
        format: "json",
      },
      {
        upstream: "testvectors_v1/ecdh_secp521r1_ecpoint_test.json",
        local: "wycheproof/ecdh_secp521r1_ecpoint_test.json",
        format: "json",
      },
    ],
  },
  xwing: {
    source_id: "xwing",
    name: "X-Wing KEM IETF CFRG draft test vectors",
    website_url: "https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem",
    repo: "dconnolly/draft-connolly-cfrg-xwing-kem",
    ref: process.env.XWING_REF,
    license: {
      declared: "CC-BY-SA-4.0 / BSD-3-Clause",
      note: "IETF CFRG draft repository vectors; pinned by commit with a per-file hash.",
    },
    files: [
      {
        upstream: "spec/test-vectors.json",
        local: "xwing/test-vectors.json",
        format: "json",
        coverage: "X-Wing-768",
      },
    ],
  },
  hpke: {
    source_id: "hpke-rfc9180",
    name: "HPKE RFC 9180 test vectors (CFRG draft repository)",
    website_url: "https://github.com/cfrg/draft-irtf-cfrg-hpke",
    repo: "cfrg/draft-irtf-cfrg-hpke",
    ref: process.env.HPKE_REF,
    license: {
      declared: "Simplified BSD / IETF Trust",
      note: "CFRG draft repository test vectors; pinned by commit with a per-file hash.",
    },
    files: [
      {
        upstream: "test-vectors.json",
        local: "hpke/rfc9180_test_vectors.json",
        format: "json",
        coverage: "HPKE",
      },
    ],
  },
  brycx: {
    source_id: "brycx",
    name: "brycx Test-Vector-Generation PBKDF2-HMAC-SHA2 vectors (RFC 6070-derived)",
    website_url: "https://github.com/brycx/Test-Vector-Generation",
    repo: "brycx/Test-Vector-Generation",
    ref: process.env.BRYCX_REF,
    license: {
      declared: "MIT",
      note: "RFC 6070-derived PBKDF2-HMAC-SHA2 vectors; MIT-licensed, pinned by commit with a per-file hash.",
    },
    files: [
      {
        upstream: "PBKDF2/pbkdf2-hmac-sha2-test-vectors.md",
        local: "pbkdf2/brycx_pbkdf2_hmac_sha2.md",
        format: "text",
        coverage: "PBKDF2",
      },
    ],
  },
  bip340: {
    source_id: "bip340",
    name: "BIP-340 Schnorr signature test vectors",
    website_url: "https://github.com/bitcoin/bips",
    repo: "bitcoin/bips",
    ref: process.env.BIP340_REF,
    license: {
      declared: "BSD-2-Clause",
      note: "BIP text and vectors are BSD-2-Clause; pinned by commit with a per-file hash.",
    },
    files: [
      {
        // The secp256k1/BIP-340 coverage row is set by the Wycheproof ECDSA
        // file; record this file and hash without a second coverage write.
        upstream: "bip-0340/test-vectors.csv",
        local: "bip340/test-vectors.csv",
        format: "csv",
      },
    ],
  },
  rfc8032: {
    source_id: "rfc8032",
    name: "RFC 8032 Ed25519 sign.input corpus (Go standard library testdata)",
    website_url: "https://github.com/golang/go",
    repo: "golang/go",
    ref: process.env.RFC8032_REF,
    license: {
      declared: "BSD-3-Clause",
      note: "Go standard library crypto/ed25519 testdata; gzip decompressed on vendoring.",
    },
    files: [
      {
        upstream: "src/crypto/ed25519/testdata/sign.input.gz",
        local: "rfc8032/ed25519_sign_input.txt",
        format: "text",
        gunzip: true,
      },
    ],
  },
};

function rawUrl(repo, ref, upstream) {
  return `https://raw.githubusercontent.com/${repo}/${ref}/${upstream}`;
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function fetchBytes(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`fetch failed (${response.status}) for ${url}`);
  }
  return Buffer.from(await response.arrayBuffer());
}

function upsert(list, keyName, keyValue, entry) {
  const index = list.findIndex((item) => item[keyName] === keyValue);
  if (index === -1) {
    list.push(entry);
  } else {
    list[index] = { ...list[index], ...entry };
  }
}

async function vendorSource(source, provenance) {
  if (!source.ref) {
    throw new Error(
      `missing pinned commit for "${source.source_id}"; set the *_REF environment variable to a reviewed commit`,
    );
  }
  if (!/^[0-9a-f]{40}$/.test(source.ref)) {
    throw new Error(
      `"${source.source_id}" ref must be a full 40-character commit SHA (got "${source.ref}")`,
    );
  }

  const existingSource = provenance.sources.find(
    (candidate) => candidate.source_id === source.source_id,
  );
  // Re-fetching an already-reviewed commit must be byte-for-byte idempotent so
  // CI can prove that vendoring reproduces the committed corpus. A new commit
  // receives the actual refresh date and must be reviewed and committed before
  // its adapters are allowed to execute in CI.
  const retrievedAt =
    existingSource?.commit === source.ref &&
    typeof existingSource.retrieved_at === "string"
      ? existingSource.retrieved_at
      : RETRIEVED_AT;

  upsert(provenance.sources, "source_id", source.source_id, {
    source_id: source.source_id,
    name: source.name,
    website_url: source.website_url,
    source_tree_url: `https://github.com/${source.repo}/tree/${source.ref}`,
    commit: source.ref,
    retrieved_at: retrievedAt,
    license: source.license,
  });

  for (const file of source.files) {
    const url = rawUrl(source.repo, source.ref, file.upstream);
    const raw = await fetchBytes(url);
    const bytes = file.gunzip ? gunzipSync(raw) : raw;
    const target = join(EXTERNAL_DIR, file.local);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes);

    upsert(provenance.files, "local_path", file.local, {
      source_id: source.source_id,
      local_path: file.local,
      upstream_url: url,
      sha256: sha256Hex(bytes),
      format: file.format,
    });

    if (file.coverage) {
      upsert(provenance.coverage, "reallyme_algorithm", file.coverage, {
        reallyme_algorithm: file.coverage,
        source_id: source.source_id,
        status: "vendored_sample",
        upstream_path: file.upstream,
      });
    }

    process.stdout.write(`vendored ${file.local} (${bytes.length} bytes)\n`);
  }
}

async function checkSource(source, provenance) {
  const provenanceSource = provenance.sources.find(
    (candidate) => candidate.source_id === source.source_id,
  );
  if (provenanceSource === undefined) {
    throw new Error(`missing provenance source for "${source.source_id}"`);
  }
  const commit = provenanceSource.commit;
  if (typeof commit !== "string" || !/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error(`provenance source "${source.source_id}" has an invalid commit`);
  }
  const expectedSourceTreeUrl = `https://github.com/${source.repo}/tree/${commit}`;
  if (provenanceSource.source_tree_url !== expectedSourceTreeUrl) {
    throw new Error(`provenance source tree URL does not match "${source.source_id}"`);
  }

  for (const file of source.files) {
    const provenanceFile = provenance.files.find(
      (candidate) => candidate.local_path === file.local,
    );
    if (provenanceFile === undefined || provenanceFile.source_id !== source.source_id) {
      throw new Error(`missing provenance file entry for "${file.local}"`);
    }
    const expectedUrl = rawUrl(source.repo, commit, file.upstream);
    if (provenanceFile.upstream_url !== expectedUrl) {
      throw new Error(`provenance URL does not match "${file.local}"`);
    }

    const upstreamRaw = await fetchBytes(expectedUrl);
    const upstreamBytes = file.gunzip ? gunzipSync(upstreamRaw) : upstreamRaw;
    const committedBytes = await readFile(join(EXTERNAL_DIR, file.local));
    const upstreamDigest = sha256Hex(upstreamBytes);
    if (
      provenanceFile.sha256 !== upstreamDigest ||
      !committedBytes.equals(upstreamBytes)
    ) {
      throw new Error(`committed corpus does not match pinned upstream bytes for "${file.local}"`);
    }
    process.stdout.write(`verified ${file.local} against ${commit}\n`);
  }
}

async function main() {
  const arguments_ = process.argv.slice(2);
  const checkMode = arguments_[0] === "--check";
  const requested = checkMode ? arguments_.slice(1) : arguments_;
  const names = requested.length > 0 ? requested : Object.keys(SOURCES);
  for (const name of names) {
    if (!SOURCES[name]) {
      throw new Error(`unknown source "${name}"; known: ${Object.keys(SOURCES).join(", ")}`);
    }
  }

  const provenance = JSON.parse(await readFile(PROVENANCE_PATH, "utf8"));
  if (
    !Array.isArray(provenance.sources) ||
    !Array.isArray(provenance.files) ||
    !Array.isArray(provenance.coverage)
  ) {
    throw new Error("provenance manifest arrays are missing or invalid");
  }

  if (checkMode) {
    for (const name of names) {
      await checkSource(SOURCES[name], provenance);
    }
    process.stdout.write("committed supplementary corpora match pinned upstream bytes\n");
    return;
  }

  for (const name of names) {
    await vendorSource(SOURCES[name], provenance);
  }

  provenance.files.sort((a, b) => a.local_path.localeCompare(b.local_path));
  await writeFile(PROVENANCE_PATH, `${JSON.stringify(provenance, null, 2)}\n`);
  process.stdout.write("updated provenance.json\n");
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
