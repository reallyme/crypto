# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify locked cryptography packages with proof-only modules."""

import argparse
import hashlib
import io
import json
import re
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
    if package_identity(local_backend) != (backend["name"], backend["version"], None, None):
        raise VerificationError(
            f"the proof package does not match the locked {backend['name'].upper()} version"
        )
    for package in selected:
        if package is not local_backend and package_identity(package) not in locked:
            raise VerificationError(
                f"proof dependency differs from Cargo.lock: {package['name']} {package['version']}"
            )


def prepare_archive(archive, digest, destination, package_dir):
    data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise VerificationError("source archive checksum differs from its pin")

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
                raise VerificationError("source archive contains an unexpected entry")
            seen.add(path)
        package.extractall(destination, members=members, filter="data")


def prepare_backend_package(destination, lock_text, backend):
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
            if package["name"] == backend["name"]
            and package["version"] == backend["version"]
            and package["source"] == CRATES_IO
        ],
        "crates.io proof package in workspace metadata",
    )

    source_dir = Path(source["manifest_path"]).parent
    package_dir = f"{backend['name']}-{backend['version']}"
    registry_dir = source_dir.parents[2]
    if source_dir.name != package_dir or source_dir.parents[1] != registry_dir / "src":
        raise VerificationError("proof package is not in the expected Cargo registry source layout")
    archive = registry_dir / "cache" / source_dir.parent.name / f"{package_dir}.crate"
    prepare_archive(archive, backend["checksum"], destination, package_dir)
    package = destination / package_dir

    manifest = package / "Cargo.toml"
    # The proof and vector checks use a normal library build. Upstream benchmark
    # and test dependencies are outside the reviewed dependency graph.
    upstream = manifest.read_text(encoding="utf-8")
    runtime_manifest = re.sub(
        r"^\[dev-dependencies(?:\.[^\n\]]+)?\]\n.*?(?=^\[|\Z)",
        "",
        upstream,
        flags=re.MULTILINE | re.DOTALL,
    )
    expected_manifest = tomllib.loads(upstream)
    expected_manifest.pop("dev-dependencies", None)
    if tomllib.loads(runtime_manifest) != expected_manifest:
        raise VerificationError("removing dev dependencies would change the runtime manifest")
    manifest.write_text(runtime_manifest + "\n", encoding="utf-8")

    # Seed the temporary resolver with the workspace lockfile. The single
    # package whose source changes is the package installed from the archive
    # above. Cargo prunes unrelated workspace packages during resolution.
    locked_source = f'\nsource = "{CRATES_IO}"\nchecksum = "{backend["checksum"]}"'
    sections = lock_text.split("\n[[package]]\n")
    matches = [
        index
        for index, section in enumerate(sections[1:], start=1)
        if tomllib.loads(section) == backend
    ]
    index = exactly_one(matches, "proof package lockfile section")
    if sections[index].count(locked_source) != 1:
        raise VerificationError("unexpected proof package lockfile layout")
    sections[index] = sections[index].replace(locked_source, "")
    (package / "Cargo.lock").write_text("\n[[package]]\n".join(sections), encoding="utf-8")

    return manifest


def locked_dependency(packages, owner, name):
    matches = [
        reference.split(maxsplit=2)
        for reference in owner.get("dependencies", [])
        if reference.partition(" ")[0] == name
    ]
    reference = exactly_one(matches, f"{owner['name']} dependency on {name}")
    return exactly_one(
        [
            package
            for package in packages
            if package["name"] == name
            and (len(reference) == 1 or package["version"] == reference[1])
            and (len(reference) < 3 or f"({package.get('source')})" == reference[2])
        ],
        f"locked dependency for {owner['name']}",
    )


def locked_backend(name="hpke"):
    root_lock = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
    packages = tomllib.loads(root_lock)["package"]
    if name == "keccak":
        sha3_wrapper = exactly_one(
            [package for package in packages if package["name"] == "reallyme-crypto-sha3-256"],
            "SHA3-256 wrapper in Cargo.lock",
        )
        sha3 = locked_dependency(packages, sha3_wrapper, "sha3")
        backend = locked_dependency(packages, sha3, "keccak")
    else:
        backend = exactly_one(
            [package for package in packages if package["name"] == name],
            "proof package in Cargo.lock",
        )
    if backend.get("source") != CRATES_IO or "checksum" not in backend:
        raise VerificationError("the proof package must resolve to a checksummed crates.io release")
    return root_lock, packages, backend


def resolve_backend_package(manifest, options, packages, backend):
    subprocess.run(
        [
            "cargo", "metadata", "--offline", "--format-version", "1",
            "--manifest-path", manifest, *options,
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        check=True,
    )
    resolved = manifest.with_name("Cargo.lock").read_text(encoding="utf-8")
    verify_resolution(resolved, packages, backend)
    return resolved


def restrict_ml_kem_to_one_chunk(source):
    # All polynomial chunks go through the same loop body. Retain that body
    # from the checksummed source and give it precisely one complete chunk so
    # Kani can quantify over the data without unrolling the other 127 chunks.
    encoding = source / "encoding.rs"
    text = encoding.read_text(encoding="utf-8")
    for original, projected in (
        ("let vc = vals.chunks(val_step);", "let vc = vals[..val_step].chunks(val_step);"),
        ("let bc = bytes.chunks_mut(byte_step);", "let bc = bytes[..byte_step].chunks_mut(byte_step);"),
        ("let vc = vals.chunks_mut(val_step);", "let vc = vals[..val_step].chunks_mut(val_step);"),
        ("let bc = bytes.chunks(byte_step);", "let bc = bytes[..byte_step].chunks(byte_step);"),
    ):
        if text.count(original) != 1:
            raise VerificationError("module-lattice chunk layout changed")
        text = text.replace(original, projected)
    encoding.write_text(text, encoding="utf-8")


def verify_harness(name, harness_name, source_name, module, features):
    root_lock, packages, backend = locked_backend(name)

    with tempfile.TemporaryDirectory(prefix=f"{name}-verification-") as directory:
        manifest = prepare_backend_package(Path(directory), root_lock, backend)
        source = manifest.parent / "src"
        if name == "module-lattice":
            restrict_ml_kem_to_one_chunk(source)
        harness = Path(__file__).with_name(harness_name)
        module_path = source / source_name
        (module_path.parent / harness.name).write_bytes(harness.read_bytes())
        with module_path.open("a", encoding="utf-8") as package_source:
            package_source.write(module)
        proof_lock = manifest.with_name("Cargo.lock")
        resolved = resolve_backend_package(manifest, features, packages, backend)
        # Kani does not accept Cargo's --locked option. Resolve offline first,
        # then reject any lockfile change made during verification.
        subprocess.run(
            [
                "cargo",
                "kani",
                "--manifest-path", manifest,
                "--target-dir", manifest.parent / "target",
                *features,
                "--lib",
                "--harness", harness.stem,
                "-Z", "unstable-options",
                "--harness-timeout", "15m",
                "--jobs", "2",
                "--output-format", "terse",
            ],
            cwd=ROOT,
            env={**environ, "CARGO_NET_OFFLINE": "true"},
            check=True,
        )
        if proof_lock.read_text(encoding="utf-8") != resolved:
            raise VerificationError("Cargo changed the reviewed resolution during verification")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "package",
        choices=("hpke", "module-lattice", "x25519-dalek", "aes-kw", "keccak"),
        default="hpke",
        nargs="?",
    )
    args = parser.parse_args()
    if args.package == "hpke":
        verify_harness("hpke", "aead_state_proof_tests.rs", "aead.rs", PROOF_MODULE, FEATURE_OPTIONS)
    elif args.package == "module-lattice":
        verify_harness("module-lattice", "ml_kem_encoding_proof_tests.rs", "lib.rs",
                       "\n#[cfg(kani)]\nmod ml_kem_encoding_proof_tests;\n",
                       ("--no-default-features", "--features", "ctutils,zeroize"))
    elif args.package == "x25519-dalek":
        verify_harness("x25519-dalek", "x25519_contributory_proof_tests.rs", "x25519.rs",
                       '\n#[cfg(kani)]\n#[path = "x25519_contributory_proof_tests.rs"]\n'
                       "mod x25519_contributory_proof_tests;\n",
                       ("--no-default-features", "--features", "static_secrets,zeroize"))
    elif args.package == "aes-kw":
        verify_harness("aes-kw", "aes_kw_schedule_proof_tests.rs", "lib.rs",
                       "\n#[cfg(kani)]\nmod aes_kw_schedule_proof_tests;\n",
                       ("--no-default-features", "--features", "zeroize"))
    else:
        verify_harness("keccak", "keccak_round_proof_tests.rs", "backends/soft.rs",
                       '\n#[cfg(kani)]\n#[path = "keccak_round_proof_tests.rs"]\n'
                       "mod keccak_round_proof_tests;\n",
                       ("--no-default-features",))


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
        sys.exit(f"locked package verification failed: {error}")
