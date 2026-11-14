# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify the locked HPKE backend with an appended, proof-only module."""

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from os import environ
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[2]
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
FEATURE_OPTIONS = ("--no-default-features", "--features", "aes,alloc,chacha,x25519")
PROOF_MODULE = """
#[cfg(kani)]
#[path = "aead_state_proof_tests.rs"]
mod aead_state_proof_tests;
"""


class VerificationError(Exception):
    """The verifier could not establish the identity of its proof input."""


def exactly_one(records, description):
    if len(records) != 1:
        raise VerificationError(f"expected exactly one {description}")
    return records[0]


def package_identity(package):
    return (
        package["name"],
        package["version"],
        package.get("source"),
        package.get("checksum"),
    )


def verify_resolution(lock_text, workspace_packages, backend):
    locked = {package_identity(package) for package in workspace_packages}
    selected = tomllib.loads(lock_text)["package"]
    local_backend = exactly_one(
        [package for package in selected if package.get("source") is None],
        "local proof package",
    )
    if package_identity(local_backend) != ("hpke", backend["version"], None, None):
        raise VerificationError("the proof package does not match the locked HPKE version")
    for package in selected:
        if package is not local_backend and package_identity(package) not in locked:
            raise VerificationError(
                f"proof dependency differs from Cargo.lock: {package['name']} {package['version']}"
            )


def prepare_archive(archive, digest, destination, package_dir):
    data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise VerificationError("HPKE registry archive checksum differs from Cargo.lock")

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as package:
        members = package.getmembers()
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (
                not path.parts
                or path.parts[0] != package_dir
                or ".." in path.parts
                or path in seen
                or not (member.isfile() or member.isdir())
            ):
                raise VerificationError("HPKE archive contains an unexpected entry")
            seen.add(path)
        package.extractall(destination, members=members, filter="data")


def prepare_proof_package(destination, lock_text, backend):
    workspace_manifest = ROOT / "Cargo.toml"
    metadata = subprocess.check_output(
        [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--format-version", "1",
            "--manifest-path", workspace_manifest,
            "--no-default-features",
            "--features", "reallyme-crypto-hpke/native",
            "--filter-platform", "host-tuple",
        ],
        cwd=ROOT,
    )
    source = exactly_one(
        [
            package
            for package in json.loads(metadata)["packages"]
            if package["name"] == "hpke"
            and package["version"] == backend["version"]
            and package["source"] == CRATES_IO
        ],
        "crates.io HPKE package in workspace metadata",
    )

    source_dir = Path(source["manifest_path"]).parent
    package_dir = f"hpke-{backend['version']}"
    registry_dir = source_dir.parents[2]
    if source_dir.name != package_dir or source_dir.parents[1] != registry_dir / "src":
        raise VerificationError("HPKE is not in the expected Cargo registry source layout")
    archive = registry_dir / "cache" / source_dir.parent.name / f"{package_dir}.crate"
    prepare_archive(archive, backend["checksum"], destination, package_dir)
    package = destination / package_dir

    manifest = package / "Cargo.toml"
    # The harness is appended to a normal library build. Upstream benchmark
    # and test dependencies are outside this proof's dependency graph.
    upstream = manifest.read_text(encoding="utf-8")
    manifest_sections = upstream.split("\n[dev-dependencies.", maxsplit=1)
    if len(manifest_sections) != 2:
        raise VerificationError("HPKE manifest layout changed, review proof preparation")
    runtime_manifest = manifest_sections[0]
    expected_manifest = tomllib.loads(upstream)
    del expected_manifest["dev-dependencies"]
    if tomllib.loads(runtime_manifest) != expected_manifest:
        raise VerificationError("removing dev dependencies would change the HPKE manifest")
    manifest.write_text(runtime_manifest + "\n", encoding="utf-8")

    # Seed the temporary resolver with the workspace lockfile. The single
    # package whose source changes is HPKE itself, installed from the archive
    # above. Cargo prunes unrelated workspace packages during resolution.
    locked_source = f'\nsource = "{CRATES_IO}"\nchecksum = "{backend["checksum"]}"'
    sections = lock_text.split("\n[[package]]\n")
    matches = [
        index
        for index, section in enumerate(sections[1:], start=1)
        if tomllib.loads(section) == backend
    ]
    index = exactly_one(matches, "HPKE lockfile section")
    if sections[index].count(locked_source) != 1:
        raise VerificationError("unexpected HPKE lockfile layout")
    sections[index] = sections[index].replace(locked_source, "")
    (package / "Cargo.lock").write_text("\n[[package]]\n".join(sections), encoding="utf-8")

    harness = Path(__file__).with_name("aead_state_proof_tests.rs")
    (package / "src" / harness.name).write_bytes(harness.read_bytes())
    with (package / "src" / "aead.rs").open("a", encoding="utf-8") as aead_source:
        aead_source.write(PROOF_MODULE)
    return manifest


def main():
    root_lock = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
    packages = tomllib.loads(root_lock)["package"]
    backend = exactly_one(
        [package for package in packages if package["name"] == "hpke"],
        "HPKE package in Cargo.lock",
    )
    if backend.get("source") != CRATES_IO or "checksum" not in backend:
        raise VerificationError("HPKE must resolve to a checksummed crates.io release")

    with tempfile.TemporaryDirectory(prefix="hpke-verification-") as directory:
        manifest = prepare_proof_package(Path(directory), root_lock, backend)
        subprocess.run(
            [
                "cargo",
                "metadata",
                "--offline",
                "--format-version", "1",
                "--manifest-path", manifest,
                *FEATURE_OPTIONS,
            ],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            check=True,
        )
        proof_lock = manifest.with_name("Cargo.lock")
        resolved = proof_lock.read_text(encoding="utf-8")
        verify_resolution(resolved, packages, backend)
        # Kani does not accept Cargo's --locked option. Resolve offline first,
        # then reject any lockfile change made during verification.
        subprocess.run(
            [
                "cargo",
                "kani",
                "--manifest-path", manifest,
                *FEATURE_OPTIONS,
                "--lib",
                "--jobs", "2",
                "--output-format", "terse",
            ],
            cwd=ROOT,
            env={**environ, "CARGO_NET_OFFLINE": "true"},
            check=True,
        )
        if proof_lock.read_text(encoding="utf-8") != resolved:
            raise VerificationError("Cargo changed the reviewed resolution during verification")


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        KeyError,
        tarfile.TarError,
        subprocess.CalledProcessError,
        VerificationError,
    ) as error:
        sys.exit(f"HPKE verification failed: {error}")
