# Isolated Insigne / COSE comparison

2026-10-30. An experimental comparison using disposable test keys. This is not
an adopted wire format or a production authentication implementation. No file
under `crates/`, root dependency manifest or root lockfile is changed.

The approved scope and reuse criteria are recorded in
`mere/design_docs/mere_docs/implementation_strategy/2026-10-29_stack_reduction_plan.md`.
The objective is to find actual private grammar that could disappear, preserve
selected authority decisions, measure target/dependency costs, and expose the
signed-material migration rather than hide it behind another envelope.

## Layout

- `codec`: no_std + alloc COSE/profile and CBOR payload code; cryptography is
  supplied by a caller callback. This crate has no resident, transport, storage
  or authority policy. Its signatures are not authorization decisions.
- `comparison`: native tests with existing Personae/Insigne types and real
  Ed25519 verification. It measures selected policy and identity compatibility.
- `fixtures`: independent Python/OpenSSL wire fixtures, validated against an
  RFC 8032 test vector. The fixture provider is a test oracle, not a new shipped
  native dependency. All fixture seeds are public disposable test data.

The standalone workspace and lock keep experiment dependencies out of the
production workspace. Build artifacts belong in the shared stable target lane,
not in this directory.

## Local experimental profile

Use RFC 9052 COSE_Sign1, tagged with CBOR tag 18, and exactly these protected
headers:

| Label | Value |
|---|---|
| 1 / algorithm | RFC 9864 fully specified Ed25519, -19 |
| 3 / content type | `application/vnd.merely.delegation-certificate+cbor` or `application/vnd.merely.delegation-revocation+cbor` |
| 4 / key ID | 32 bytes, equal to the signing public key expected by the caller |

These media types and the payload below are unregistered local comparison
choices. They are not an existing Merely protocol. Unprotected headers are
empty, payload is present, and the signature is 64 bytes. External associated
data is the fixed byte string `merely/insigne/cose-comparison/v1`; it supplies
application context, not a live-channel binding. Additional, duplicate,
misplaced or unexpected headers, wrong kinds/keys, malformed payloads and
trailing data must be refused. The bounded codec accepts at most 16 KiB per
wire message; this is a comparison-profile limit, not a new production limit.

The payload uses definite-length CBOR arrays and preferred integer widths:

```text
scope = [domain: text, resource: bytes, path_prefix: text,
         actions: [sorted, unique text]]
certificate = [1, parent_kind: 0(root)|1(certificate), parent_id: bytes32,
               issuer: bytes32, subject: bytes32, scope, issued_at: u64,
               not_before: u64, expiry: null|u64, remaining_depth: u16,
               nonce: bytes32]
revocation = [1, certificate_id: bytes32, issuer: bytes32, scope,
              at_ms: u64, nonce: bytes32]
```

Payload decode checks schema and canonical re-encoding; COSE alone does not
make application payloads canonical. Signing bytes are COSE's Sig_structure
over the protected header, fixed external data and new CBOR payload. The old
private signing bytes are not wrapped as the payload. Strict Ed25519 checking
and the expected key are supplied by the native comparison tests. Parent
trust, persona/derived-key attestation, scope, depth, time, revocation and
carrier facts remain outside the codec.

## Identity and authority seam

Current `DelegationCertificate::id()` hashes legacy `signing_bytes()` with
BLAKE3. `attenuates()` compares that ID, and Notochord's checked-proof types can
only be made by its existing grammar's checks. Retaining those IDs keeps the
legacy encoder necessary. Hashing the CBOR candidate payload changes IDs,
parent links and revocation references; retained signed history cannot simply
be relabeled.

The tests may explicitly translate IDs to compare selected existing pure
scope/time/depth rules. Such an oracle is not end-to-end Notochord, custody,
secure-channel or revocation-ledger integration. Checked production proof
types must not be forged or bypassed, and no re-signing bridge may be presented
as a working production adapter.

A production cut would need an explicit new profile/ID version, issuance and
verification changes, handling of retained signed material, and an independent
security assessment of the combined profile. This comparison selects none of
those changes.

## Run and acceptance

From this directory, run the standalone workspace tests with `--locked`.
Regenerate the independent fixture bundle with `python3 fixtures/generate.py`.
All Cargo work must acquire `/home/markik/Code/testing/machine-heavy.lock` and
retain the existing limits: MemoryMax=3G, MemorySwapMax=0, CPUQuota=150%, one
Cargo job/test thread and bounded commands. Working Rust is 1.99.1; MSRV is
1.97.1. Native, Wasm and any bare-embedded claim are separate checks.

The result must name actual legacy encoder/envelope code that could disappear,
new schema/profile code that replaces it, dependency/target cost, and remaining
policy/identity migration. A second envelope or a larger private adapter is a
valid reason to retain the current implementation. Successful callback tests
or a same-library round trip alone do not establish conformance or security.

## Verified results, 2026-10-30

| Gate | Result |
|---|---|
| Rust 1.99.1 native standalone workspace | 16 tests passed; no failures or ignores |
| Rust 1.97.1 native standalone workspace | The same 16 tests passed; no failures or ignores |
| Rust 1.97.1 `wasm32-unknown-unknown` codec check | Passed, no default features |
| Rust 1.99.1 `wasm32-unknown-unknown` codec check | Passed, no default features |
| Independent fixture generation | Seven Python/OpenSSL vectors; repeat generation byte-identical |
| Changed Rust formatting and source diff | Checked separately; production source unchanged |

The 16 tests comprise 11 codec/profile cases, four native attestation/policy
cases, and one test that validates all seven external vectors and their
independent expected fields. Codec callback-plumbing tests use a synthetic
callback; cryptographic verification is supplied by the real Ed25519 native
harness and independent fixture cases. Passing these is limited wire/profile
and selected-policy evidence, not a complete peer implementation interop run,
security audit, or migration qualification.

The final build gate took 91.567 seconds wall time, used 2.1 GiB peak memory
and zero swap under the stated caps. This is an observed mixed/warm gate,
including both compilers and targets, not a controlled cold-build or deployed
runtime benchmark. Native finish times were 15.01 seconds (working compiler)
and 40.97 seconds (MSRV); codec Wasm checks finished in 17.53 and 17.14 seconds.
Build/fetch latency varies with cache and other work. Earlier RED and the
manifest/lock mismatch attempt remain in the local run logs; they do not
represent production failures.

The selected native normal/build codec tree contains 16 external package
identities: coset 0.4.2, ciborium/ciborium-io/ciborium-ll 0.2.2, half 2.7.1,
cfg-if, zerocopy/zerocopy-derive, serde/serde_core/serde_derive, proc-macro2,
quote, unicode-ident, and two syn versions. Five package names are absent from
the original root lock: coset, the three ciborium crates, and half. Existing
lock presence does not prove a package was linked into an affected consumer.
The codec tree has no native C backend/build dependency; crypto and the
legacy-policy oracle are separate harness dependencies. The standalone lock
contains 96 packages in total, including the native comparison graph; that is
not the portable codec's dependency count. Production manifests and lock are
unchanged.

Reproduce the gates in this standalone directory, through the capped lock:

```sh
cargo +1.99.1 test --workspace --locked --offline -- --test-threads=1
cargo +1.97.1 test --workspace --locked --offline -- --test-threads=1
cargo +1.97.1 check -p cose-insigne-codec --lib --no-default-features --locked --offline --target wasm32-unknown-unknown
cargo +1.99.1 check -p cose-insigne-codec --lib --no-default-features --locked --offline --target wasm32-unknown-unknown
cargo +1.99.1 tree -p cose-insigne-codec --edges normal,build --locked --offline --prefix none
```

For a fresh cache, fetch the locked sources before using `--offline`.
Bare microcontrollers, browser runtime behavior, native/mobile deployment,
whole-stack gates, and real retained signed-data migration were not tested.
The current production suite was not rerun because its files and dependency
inputs were not changed by this standalone experiment.


## Source comparison and provisional interpretation

At the pinned base, the two certificate/revocation `signing_bytes()` bodies
and their dedicated `push_scope`/`push_expiry` helpers occupy 53 source lines
(2,021 bytes, counting braces). The 8-byte length-prefix helpers `push_bytes`
and `push_str` also define signing-key salts/prefixes, so an envelope switch
does not remove them. Keeping legacy certificate IDs keeps the old signing
grammar needed for hashing as well. Attestation and secure-session transcript
grammars are outside this experiment.

The prototype codec is 312 formatted source lines (9,569 bytes), including
duplicated experimental payload types, field validation, encoding/decoding and
profile checks. This is not a minimum production-adapter estimate: reusing
existing types or a different typed serializer could change it. It is evidence
that this particular comparison establishes a standards boundary rather than
a straightforward source-size reduction. No production line has been deleted.

The useful potential benefit is independently consumable COSE signing and
format processing. It does not transfer issuer authority, derived-key
attestation, scope/depth/time, revocation/freshness or channel-binding decisions
to coset. The migration is substantive even if the serializer is made smaller.
A production recommendation must weigh an actual interchange/conformance need
against that migration and the remaining application profile.


## Recommendation

Retain this comparison and **hold production adoption**. It demonstrates a
portable signed-format boundary with independent wire evidence, but not a
straightforward net-code or authority-maintenance reduction. A meaningful
next production decision needs a concrete interchange/conformance benefit and
a versioned ID, checked-proof, parent/revocation and retained-history strategy.
It must not silently change existing identities or keep the old grammar only
to add a second envelope. Bitwarden remains deferred on its separate unresolved
net-deletion case.
