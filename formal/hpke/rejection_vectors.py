# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Build checks for rejection secrets using independent standard primitives."""

import hashlib
import json
import subprocess

from verify import VerificationError

ACVP_CORPUS = "nist-acvp/ml-kem/encap-decap/internalProjection.json"
ML_KEM_CT_LENGTH = {"ML-KEM-512": 768, "ML-KEM-768": 1088, "ML-KEM-1024": 1568}
ML_KEM_DK_LENGTH = {"ML-KEM-512": 1632, "ML-KEM-768": 2400, "ML-KEM-1024": 3168}
ML_KEM_PARAMETERS = {0x0040: "ML-KEM-512", 0x0041: "ML-KEM-768", 0x0042: "ML-KEM-1024"}
X_WING = 0x647A
SEED_BYTES = 32
SHARED_SECRET_BYTES = 32
X25519_BYTES = 32
X_WING_PUBLIC_KEY_BYTES = 1216
X_WING_PQ_CT_BYTES = ML_KEM_CT_LENGTH["ML-KEM-768"]
X_WING_LABEL = bytes.fromhex("5c2e2f2f5e5c")
# RFC 8410 DER prefix for a bare X25519 private key and public key.
X25519_PKCS8 = bytes.fromhex("302e020100300506032b656e04220420")
X25519_SPKI = bytes.fromhex("302a300506032b656e032100")


def rejection_secret(z, ciphertext):
    # FIPS 203 Algorithm 18 uses the final seed z and the full ciphertext.
    return hashlib.shake_256(z + ciphertext).digest(SHARED_SECRET_BYTES)


def check_acvp(corpus):
    cases = json.loads(corpus)
    checked = {parameter: [0, 0] for parameter in ML_KEM_CT_LENGTH}
    kem_ids = {parameter: kem_id for kem_id, parameter in ML_KEM_PARAMETERS.items()}
    vectors = []
    for group in cases["testGroups"]:
        if group["function"] != "decapsulation":
            continue
        parameter = group["parameterSet"]
        for row in group["tests"]:
            if row["reason"] not in ("modified ciphertext", "valid decapsulation"):
                raise VerificationError("unexpected ACVP decapsulation case")
            dk, ct, expected = (bytes.fromhex(row[name]) for name in ("dk", "c", "k"))
            if (
                len(dk) != ML_KEM_DK_LENGTH[parameter]
                or len(ct) != ML_KEM_CT_LENGTH[parameter]
                or len(expected) != SHARED_SECRET_BYTES
            ):
                raise VerificationError("unexpected ACVP decapsulation fixture length")
            rejected = row["reason"] == "modified ciphertext"
            if (rejection_secret(dk[-SEED_BYTES:], ct) == expected) != rejected:
                raise VerificationError("the FIPS 203 rejection formula disagrees with ACVP")
            checked[parameter][int(rejected)] += 1
            vectors.append((kem_ids[parameter], dk, ct, expected))
    if any(counts != [5, 5] for counts in checked.values()):
        raise VerificationError("expected five positive and negative ACVP cases per ML-KEM")
    return vectors


def classical_contribution(scratch, private_scalar, peer, expected_public):
    private = scratch / "x25519-private.der"
    public = scratch / "x25519-peer.der"
    private.write_bytes(X25519_PKCS8 + private_scalar)
    public.write_bytes(X25519_SPKI + peer)
    encoded_public = subprocess.check_output(
        ["openssl", "pkey", "-inform", "DER", "-in", private, "-pubout", "-outform", "DER"],
    )
    if encoded_public != X25519_SPKI + expected_public:
        raise VerificationError("reference X25519 public key differs from the X-Wing fixture")
    secret = subprocess.check_output(
        ["openssl", "pkeyutl", "-derive", "-keyform", "DER", "-inkey", private,
         "-peerform", "DER", "-peerkey", public],
    )
    if len(secret) != X25519_BYTES or not any(secret):
        raise VerificationError("expected a contributory X25519 shared secret")
    return secret


def x_wing_key_parts(private, public, enc):
    if (
        len(private) != SEED_BYTES
        or len(enc) != X_WING_PQ_CT_BYTES + X25519_BYTES
        or len(public) != X_WING_PUBLIC_KEY_BYTES
    ):
        raise VerificationError("unexpected X-Wing fixture length")
    expanded = hashlib.shake_256(private).digest(3 * SEED_BYTES)
    z = expanded[SEED_BYTES:2 * SEED_BYTES]
    return z, expanded[2 * SEED_BYTES:], public[-X25519_BYTES:]


def x_wing_classical_cases(rows, scratch):
    if len(rows) != 2 or any(row["kem_id"] != X_WING for row in rows):
        raise VerificationError("expected both published X-Wing fixture rows")

    first, second = rows
    for row, other in ((first, second), (second, first)):
        enc, private, public = (bytes.fromhex(row[name]) for name in ("enc", "skRm", "pkRm"))
        z, sk_x, pk_x = x_wing_key_parts(private, public, enc)
        alternate_enc = bytes.fromhex(other["enc"])
        if len(alternate_enc) != len(enc):
            raise VerificationError("unexpected alternate X-Wing encapsulation length")

        # Hold a known rejected ML-KEM ciphertext fixed across both cases.
        # Its fallback secret can be calculated directly from FIPS 203.
        pq = bytearray(enc[:X_WING_PQ_CT_BYTES])
        pq[0] ^= 1
        ss_m = rejection_secret(z, pq)
        peer = enc[X_WING_PQ_CT_BYTES:]
        alternate_peer = alternate_enc[X_WING_PQ_CT_BYTES:]
        ss_x = classical_contribution(scratch, sk_x, peer, pk_x)
        alternate_ss_x = classical_contribution(scratch, sk_x, alternate_peer, pk_x)
        if peer == alternate_peer or ss_x == alternate_ss_x:
            raise VerificationError("alternate X25519 input must change the classical contribution")

        expected = hashlib.sha3_256(ss_m + ss_x + peer + pk_x + X_WING_LABEL).digest()
        alternate = hashlib.sha3_256(
            ss_m + alternate_ss_x + alternate_peer + pk_x + X_WING_LABEL,
        ).digest()
        if expected == alternate:
            raise VerificationError("alternate X25519 input must change the combined secret")
        prefix = bytes(pq)
        yield private, prefix + peer, expected, prefix + alternate_peer, alternate


def cases_for_row(row, scratch):
    kem = row["kem_id"]
    enc, private, public, original = (
        bytes.fromhex(row[name]) for name in ("enc", "skRm", "pkRm", "shared_secret")
    )
    suffix = b""
    combine_input = None
    if kem == X_WING:
        ct_length = X_WING_PQ_CT_BYTES
        z, sk_x, pk_x = x_wing_key_parts(private, public, enc)
        suffix = enc[ct_length:]
        ss_x = classical_contribution(scratch, sk_x, suffix, pk_x)
        combine_input = ss_x + suffix + pk_x + X_WING_LABEL
    else:
        ct_length = ML_KEM_CT_LENGTH[ML_KEM_PARAMETERS[kem]]
        if len(private) != 2 * SEED_BYTES or len(enc) != ct_length:
            raise VerificationError("unexpected ML-KEM fixture length")
        z = private[-SEED_BYTES:]

    for offset, mask in ((0, 1), (ct_length - 1, 128)):
        modified = bytearray(enc[:ct_length])
        modified[offset] ^= mask
        expected = rejection_secret(z, modified)
        if combine_input is not None:
            expected = hashlib.sha3_256(expected + combine_input).digest()
        if expected == original:
            raise VerificationError("rejection secret equals the valid fixture secret")
        yield (kem, private, enc, original, bytes(modified) + suffix, expected)
