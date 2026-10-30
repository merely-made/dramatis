# Disposable COSE fixtures

`vectors.json` contains seven independent, synthetic COSE_Sign1 comparison
vectors. The Ed25519 private seed is intentionally public disposable test data.
It is not a Persona key, and these signatures prove wire encoding only; they
do not represent Persona-derived attestations or a verified delegation chain.

The valid certificate and revocation use the pinned profile: tag 18 around
`[protected_bstr, {}, payload_bstr, signature_bstr]`; the generator writes protected labels
in order `1, 3, 4` for algorithm, content type, and 32-byte key ID. That order
is a fixture convention; the profile authenticates the original protected
bytes and does not mandate header ordering. The
protected map and payload use definite-length CBOR and preferred integer
widths. The signature is over the CBOR encoding of
`["Signature1", protected_bstr, aad_bstr, payload_bstr]` with the profile AAD
`merely/insigne/cose-comparison/v1`. The other two vectors have valid Ed25519
signatures but intentionally violate the profile: one changes the algorithm
label to `-8`, and one duplicates key ID label `4` in the unprotected map.
Three additional cases are signed but must fail the fixed profile: one signs
with different external AAD bytes, one repeats label `1` in the protected map,
and one encodes payload version `1` using the nonpreferred two-byte integer
form. The AAD-mismatch case records both the signing AAD (`aad_hex`) and the
required profile AAD (`fixed_profile_aad_hex`); external AAD is not present in
the COSE wire item.

The revocation's certificate ID is the fixed byte string `33` repeated 32
times. It is a reference value, not a computed or paired identifier for the
certificate vector. Identifier derivation and pairing semantics belong to the
Rust harness.

Regenerate from the repository root with:

```sh
python3 support/experiments/cose-insigne-20261030/fixtures/generate.py
```

The script uses only Python's standard library and the system `openssl` CLI.
It uses a tiny explicit CBOR subset encoder, and checks the OpenSSL Ed25519
provider against RFC 8032 section 7.1 test 2 before writing fixtures. It also
verifies each emitted signature using OpenSSL.

References:

- [RFC 9052, CBOR Object Signing and Encryption (COSE): Structures and Process](https://www.rfc-editor.org/rfc/rfc9052)
- [RFC 9864, COSE Algorithms](https://www.rfc-editor.org/rfc/rfc9864)
- [RFC 8032, EdDSA: Ed25519 and Ed448](https://www.rfc-editor.org/rfc/rfc8032)
