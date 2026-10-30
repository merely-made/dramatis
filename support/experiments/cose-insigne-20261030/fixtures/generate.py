#!/usr/bin/env python3
"""Generate independent, disposable COSE_Sign1 comparison fixtures.

The CBOR writer below is deliberately small and explicit. Signatures are
produced by the system OpenSSL Ed25519 provider; no project COSE code is used.
The private seed is public synthetic test material, never a user key.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
AAD = b"merely/insigne/cose-comparison/v1"
CONTENT_TYPES = {
    "certificate": "application/vnd.merely.delegation-certificate+cbor",
    "revocation": "application/vnd.merely.delegation-revocation+cbor",
}

# RFC 8032, section 7.1, test 2. This nonempty message vector avoids the
# zero-length input limitation of OpenSSL's pkeyutl one-shot CLI interface.
RFC8032_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f"
    "5b8a319f35aba624da8cf6ed4fb8a6fb"
)
RFC8032_PUBLIC = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc"
    "9c982ccf2ec4968cc0cd55f12af4660c"
)
RFC8032_MESSAGE = bytes.fromhex("72")
RFC8032_SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540"
    "a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c"
    "387b2eaeb4302aeeb00d291612bb0c00"
)

# Fixed, publicly disclosed seed for disposable fixtures only.
FIXTURE_SEED = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)


def head(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("CBOR argument must be nonnegative")
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError("integer exceeds CBOR uint64")


def cbor(value: object) -> bytes:
    """Encode the fixture's CBOR subset with definite lengths/minimal widths."""
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(
            cbor(key) + cbor(item) for key, item in value.items()
        )
    raise TypeError(f"unsupported fixture CBOR value: {type(value).__name__}")


def openssl_key_files(seed: bytes, directory: Path) -> tuple[Path, Path, bytes]:
    private_der = directory / "ed25519-private.der"
    public_der = directory / "ed25519-public.der"
    # RFC 8410 PKCS#8 wrapper around the raw Ed25519 seed.
    private_der.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + seed)
    derived = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-in", str(private_der),
         "-pubout", "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    prefix = bytes.fromhex("302a300506032b6570032100")
    if not derived.startswith(prefix) or len(derived) != len(prefix) + 32:
        raise RuntimeError("OpenSSL emitted an unexpected Ed25519 public-key encoding")
    public = derived[len(prefix):]
    public_der.write_bytes(derived)
    return private_der, public_der, public


def sign(private_der: Path, message: bytes, directory: Path, name: str) -> bytes:
    message_path = directory / f"{name}.bin"
    message_path.write_bytes(message)
    return subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_der),
         "-keyform", "DER", "-in", str(message_path)],
        check=True, capture_output=True,
    ).stdout


def verify(public_der: Path, message: bytes, signature: bytes,
           directory: Path, name: str) -> None:
    message_path = directory / f"{name}.verify.bin"
    signature_path = directory / f"{name}.sig"
    message_path.write_bytes(message)
    signature_path.write_bytes(signature)
    subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey",
         str(public_der), "-keyform", "DER", "-in", str(message_path),
         "-sigfile", str(signature_path)],
        check=True, capture_output=True,
    )


def scope() -> list[object]:
    return ["example.test", b"\x10" * 32, "/notes/", ["read", "write"]]


def expected_fields(kind: str, payload: list[object]) -> dict[str, object]:
    scope_value = payload[5] if kind == "certificate" else payload[3]
    decoded_scope = {
        "domain": scope_value[0],
        "resource_hex": scope_value[1].hex(),
        "path_prefix": scope_value[2],
        "actions": scope_value[3],
    }
    if kind == "certificate":
        return {
            "version": payload[0], "parent_kind": payload[1],
            "parent_id_hex": payload[2].hex(), "issuer_hex": payload[3].hex(),
            "subject_hex": payload[4].hex(), "scope": decoded_scope,
            "issued_at_ms": payload[6], "not_before_ms": payload[7],
            "expiry_ms": payload[8], "remaining_depth": payload[9],
            "nonce_hex": payload[10].hex(),
        }
    return {
        "version": payload[0], "certificate_id_hex": payload[1].hex(),
        "issuer_hex": payload[2].hex(), "scope": decoded_scope,
        "at_ms": payload[4], "nonce_hex": payload[5].hex(),
    }


def build_vector(name: str, kind: str, payload_value: list[object], seed: bytes,
                 public: bytes, private_der: Path, public_der: Path,
                 directory: Path, *, alg: int = -19,
                 unprotected: dict[object, object] | None = None,
                 aad: bytes = AAD, protected_override: bytes | None = None,
                 payload_override: bytes | None = None,
                 expected_profile_error: str | None = None) -> dict[str, object]:
    content_type = CONTENT_TYPES[kind]
    protected_map: dict[object, object] = {1: alg, 3: content_type, 4: public}
    protected = protected_override if protected_override is not None else cbor(protected_map)
    payload = payload_override if payload_override is not None else cbor(payload_value)
    sig_structure = cbor(["Signature1", protected, aad, payload])
    signature = sign(private_der, sig_structure, directory, name)
    if len(signature) != 64:
        raise RuntimeError(f"OpenSSL returned {len(signature)} signature bytes")
    verify(public_der, sig_structure, signature, directory, name)
    unprotected_bytes = cbor(unprotected or {})
    wire = head(6, 18) + cbor([protected, unprotected or {}, payload, signature])
    if expected_profile_error is None:
        if aad != AAD:
            expected_profile_error = "external_aad_mismatch"
        elif protected_override is not None:
            expected_profile_error = "duplicate_protected_header"
        elif payload_override is not None:
            expected_profile_error = "nonpreferred_payload_integer"
        elif alg != -19:
            expected_profile_error = "wrong_algorithm"
        elif unprotected:
            expected_profile_error = "unprotected_key_id"
    profile_valid = expected_profile_error is None
    return {
        "name": name,
        "kind": kind,
        "profile_valid": profile_valid,
        "expected_profile_error": expected_profile_error,
        "seed_hex": seed.hex(),
        "public_key_hex": public.hex(),
        "aad_hex": aad.hex(),
        "fixed_profile_aad_hex": AAD.hex(),
        "protected_hex": protected.hex(),
        "unprotected_hex": unprotected_bytes.hex(),
        "payload_hex": payload.hex(),
        "sig_structure_hex": sig_structure.hex(),
        "signature_hex": signature.hex(),
        "wire_hex": wire.hex(),
        "expected_fields": expected_fields(kind, payload_value),
    }


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="cose-fixtures-") as temporary:
        scratch = Path(temporary)
        rfc_private, rfc_public_der, rfc_public = openssl_key_files(RFC8032_SEED, scratch)
        if rfc_public != RFC8032_PUBLIC:
            raise RuntimeError("OpenSSL public key failed RFC 8032 test 2")
        rfc_sig = sign(rfc_private, RFC8032_MESSAGE, scratch, "rfc8032")
        if rfc_sig != RFC8032_SIGNATURE:
            raise RuntimeError("OpenSSL signature failed RFC 8032 test 2")
        verify(rfc_public_der, RFC8032_MESSAGE, RFC8032_SIGNATURE, scratch, "rfc8032")

        private_der, public_der, public = openssl_key_files(FIXTURE_SEED, scratch)
        parent_id = bytes.fromhex("11" * 32)
        subject = bytes.fromhex("22" * 32)
        certificate_id_reference = bytes.fromhex("33" * 32)
        cert_payload = [
            1, 0, parent_id, public, subject, scope(),
            1_798_747_200_000, 1_798_747_200_000, 1_801_929_600_000, 2,
            bytes.fromhex("44" * 32),
        ]
        revocation_payload = [
            1, certificate_id_reference, public, scope(), 1_799_000_000_000,
            bytes.fromhex("55" * 32),
        ]
        duplicate_protected = (
            head(5, 4) + cbor(1) + cbor(-19) + cbor(1) + cbor(-19)
            + cbor(3) + cbor(CONTENT_TYPES["certificate"])
            + cbor(4) + cbor(public)
        )
        nonpreferred_version_payload = (
            head(4, len(cert_payload)) + b"\x18\x01"
            + b"".join(cbor(item) for item in cert_payload[1:])
        )
        wrong_aad = b"merely/insigne/cose-comparison/other"
        vectors = [
            build_vector("certificate_valid", "certificate", cert_payload,
                         FIXTURE_SEED, public, private_der, public_der, scratch),
            build_vector("revocation_valid", "revocation", revocation_payload,
                         FIXTURE_SEED, public, private_der, public_der, scratch),
            build_vector("certificate_wrong_alg", "certificate", cert_payload,
                         FIXTURE_SEED, public, private_der, public_der, scratch, alg=-8),
            build_vector("certificate_unprotected_kid", "certificate", cert_payload,
                         FIXTURE_SEED, public, private_der, public_der, scratch,
                         unprotected={4: public}),
            build_vector("certificate_wrong_external_aad", "certificate", cert_payload,
                         FIXTURE_SEED, public, private_der, public_der, scratch,
                         aad=wrong_aad),
            build_vector("certificate_duplicate_protected_label", "certificate", cert_payload,
                         FIXTURE_SEED, public, private_der, public_der, scratch,
                         protected_override=duplicate_protected),
            build_vector("certificate_nonpreferred_payload_integer", "certificate", cert_payload,
                         FIXTURE_SEED, public, private_der, public_der, scratch,
                         payload_override=nonpreferred_version_payload),
        ]
    document = {
        "format": "merely-insigne-cose-sign1-comparison-fixtures-v1",
        "synthetic_disposable_data": True,
        "crypto_provider": "system OpenSSL Ed25519 CLI; independently RFC 8032 test-2 checked",
        "cbor_encoder": "explicit minimal definite-length subset in generate.py",
        "limitations": [
            "Signatures authenticate this wire structure only; they are not Persona-derived attestations.",
            "The revocation certificate_id is a fixed 0x33 reference and is not paired to a computed certificate identifier.",
        ],
        "vectors": vectors,
    }
    (HERE / "vectors.json").write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {HERE / 'vectors.json'} ({len(vectors)} vectors)")


if __name__ == "__main__":
    main()
