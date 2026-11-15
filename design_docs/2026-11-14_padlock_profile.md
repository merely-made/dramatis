# The padlock: a COSE_Encrypt profile for the wallet root

**Date:** 2026-11-14
**Status:** specification. Phase 1 is implemented: the platform-independent container in
`crates/castellan/src/custody/padlock.rs` and `padlock/`, its published-vector tests, the
profile's own vectors and their independent cross-check. Phase 2 is not built: the wallet
wiring and the binding check, the OS slots (DPAPI, Keychain, Secret Service glue), the file
writer, migration, and the vault's own move to NFC. Decision: **custody D8** in the
[custody plan](2026-10-28_custody_plan.md). Vectors, conformance table and sources:
[padlock_profile_vectors](2026-11-14_padlock_profile_vectors.md).
**Drawn from:** the draft `Code/testing/engine-split/padlock_cose_profile_draft.md`
(2026-11-14) with every open point replaced by its ruling (§ 6), and the research behind it
(`research_padlock_container.md`, `research_unlock_pairing_totp.md` Part 1,
`study_dramatis_stores_pairing_otp.md` Part 1, same directory).

**How to read it.** MUST, SHOULD and MAY are used in the RFC 2119 / RFC 8174 sense, only in
capitals. Each normative statement names its origin: **[std: RFC n §x]** when the standard
already requires it, **[profile]** when this profile adds it. Every RFC quote here was
re-checked against the RFC text on 2026-11-14 (sources in the vectors document).

---

## 1. Scope

### 1.1 What the padlock is

One random 32-byte **wallet root**, encrypted once as the content of one COSE_Encrypt
message. Its content key (CEK) is wrapped separately for each **unlock method** ("slot");
each slot is one COSE_recipient. Any one working slot yields the CEK, and the CEK yields the
root. The root then keys the wallet's sealed-record store, as today's DPAPI root does
(`SealedRecordStorage::open_with_key`, `crates/personae/src/sealed_record_storage.rs`).

The owner's design: "use dpapi, keychain, secret service; wrap root with passphrase across
all, so you unlock (OS) a padlock (us). then we can do stuff like 2factor, pins, biometrics,
passphrases for that padlock".

### 1.2 What it protects, and against whom

- **Offline disk theft.** A copy of the disk alone does not yield the root without breaking
  a slot. A passphrase slot is as strong as the passphrase's entropy times the Argon2id cost;
  an OS slot is as strong as the store that holds its KEK (DPAPI's logon-bound master key,
  the data-protection Keychain, the Secret Service collection).
- **Other OS users** on the same machine: every slot type refuses them.
- **The padlock is as strong as its weakest slot** against each kind of attacker. Adding a
  convenience slot adds a door; it never strengthens another [profile, plain statement].

### 1.3 What it does not protect against

- **Same-user processes on Windows and Linux.** While a DPAPI or Secret Service slot exists, a
  process of the same user can open the padlock (`2026-10-08_vault_threat_statement.md`, "On
  Windows (AutoOs), any of them can ask DPAPI to unseal").
- **Revocation of a removed method.** Removing a slot deletes one array element; a copy of
  the file taken before still opens with the removed method and yields the same root. Only a
  new root (§ 4.5) changes that [profile, plain statement].
- **Stripping.** The recipient list is not an input to the content AEAD (RFC 9052 §5.3
  defines `Enc_structure` as context, protected and external_aad only). Anyone with write
  access can delete slots: that locks the owner out of those methods and opens nothing. The
  profile adds no check of its own (OP 12, § 6).
- **Minting.** Whoever can write the file can build a valid container around a root they
  chose, once a slot exists whose input they can produce (an asymmetric slot's public key, or
  a same-user DPAPI call). COSE leaves this to the application: "a trust decision on a key
  needs to be made" [RFC 9052 §12]. What binds a container to this wallet is the check after
  unlock (§ 4.2 step 6, OP 9).
- Out of scope: the vault's `passphrase_root.rs` format (it keeps its format; only its
  normalisation moves, § 3.5), pairing, OTP, remote approval, memory hygiene after unlock.

---

## 2. Terms

| term | meaning |
|---|---|
| root | the 32-byte wallet root: the plaintext |
| CEK | the 32-byte content-encryption key; random; wrapped once per slot |
| KEK | a slot's 32-byte A256KW key |
| slot | one COSE_recipient; one unlock method |
| profile slot | a slot of a kind this reader implements (§ 3.4) |
| foreign slot | any other well-formed slot: never tried, kept byte for byte (§ 5.4) |
| container | the whole COSE_Encrypt_Tagged item; one file |

---

## 3. The container

### 3.1 CDDL

A narrowing of RFC 9052's CDDL. Names starting `pl-` are this profile's.

```cddl
padlock = #6.96(padlock-encrypt)              ; COSE_Encrypt_Tagged [RFC 9052 §5.1]

padlock-encrypt = [
  protected   : bstr .cbor pl-body-protected, ; exactly h'A2011818036E6D6572652E7061646C6F636B2F31'
  unprotected : { 5 => bstr .size 12 },       ; IV, nothing else
  ciphertext  : bstr .size 48,                ; 32-byte root + 16-byte tag
  recipients  : [1*16 pl-slot]
]

pl-body-protected = {
  1 => 24,                                    ; alg: ChaCha20/Poly1305 (OP 1)
  3 => "mere.padlock/1",                      ; content type: profile and version (OP 2)
}

pl-slot = pl-pass-slot / pl-kek-slot / pl-foreign-slot

pl-pass-slot = [                              ; kid method "pass"
  protected   : bstr .size 0,                 ; "MUST be empty" [RFC 9053 §6.2.1]
  unprotected : {
    1 => -5,                                  ; alg: A256KW
    4 => pl-kid,
    -65537 => 2,                              ; pl-kdf: Argon2id (RFC 9106 y = 2)
    -65538 => bstr .size 16,                  ; pl-kdf-salt
    -65539 => uint,                           ; pl-kdf-m, KiB
    -65540 => uint,                           ; pl-kdf-t
    -65541 => uint,                           ; pl-kdf-p
    -65542 => 19,                             ; pl-kdf-v (0x13)
  },
  ciphertext  : bstr .size 40                 ; AES-KW of the 32-byte CEK
]

pl-kek-slot = [                               ; kid method "dpapi", "keychain" or "secsvc"
  protected   : bstr .size 0,
  unprotected : {
    1 => -5,
    4 => pl-kid,
    ? -65543 => bstr .size (0..2048),         ; pl-os-blob: opaque OS data (OP 11)
  },
  ciphertext  : bstr .size 40
]

; Any other COSE_recipient that passes § 5's generic rules: skipped, kept (OP 14).
pl-foreign-slot = [ bstr, { 4 => pl-kid, * label => any }, bstr / nil, ? [+ any] ]

pl-kid = bstr .size (3..64)                   ; ASCII "<method>/<id>", § 3.4
```

Held for later slot kinds (not implemented; § 3.7): `-65544` pl-fido-cred, `-65545`
pl-fido-salt. `-65546` is not assigned (the draft's slot-list MAC, ruled out by OP 12).

### 3.2 The body

- **Tag.** The container MUST be `COSE_Encrypt_Tagged`, tag 96 [profile, OP 3]. RFC 9052
  §5.1 allows either form: "The COSE_Encrypt structure can be encoded as either tagged or
  untagged, depending on the context it will be used in." The tag costs two bytes and makes
  the file self-describing, as Eidetic's `mere.pack/2` Sign1 is.
- **alg** MUST be in the protected bucket [std: RFC 9052 §3.1: alg "MUST be authenticated
  where the ability to do so exists"]. The profile allows exactly ChaCha20/Poly1305, 24
  [profile, OP 1]: the house's at-rest AEAD (`passphrase_root.rs`, `passphrase_storage.rs`
  and the sealed records all use `chacha20poly1305` 0.11).
- **Version.** The protected `content type` (label 3) MUST be the text `"mere.padlock/1"`
  [profile, OP 2]. It is a registered label; the content AEAD authenticates it; a reader sees
  it before any key is derived, so it refuses an unknown version without running Argon2; it
  is the house pattern (Eidetic's `content type` `mere.pack/2`). It fits RFC 9052 §3.1's
  `<type-name>/<subtype-name>` syntax without being a registered media type.
- **No other protected parameter** [profile]. No `crit` anywhere (R7): the profile defines no
  critical extension.
- **Unprotected:** exactly the IV (label 5), 12 bytes [std: RFC 9053 §4.3, a 96-bit nonce],
  fresh from the OS RNG for every content encryption [std: RFC 9053 §4.3.1, "The key and
  nonce values MUST be a unique pair for every invocation"].
- **Ciphertext:** the AEAD of exactly the 32-byte root, 48 bytes. Nothing else is inside
  [profile]: a wallet identifier is not secret, a creation time serves no operation, and every
  plaintext has the same length so padding hides nothing.
- **external_aad** is empty [profile, OP 10]. The content type already binds profile and
  version, and any COSE library reproduces the AAD:

```
protected       A2 01 18 18 03 6E 6D6572652E7061646C6F636B2F31            (20 bytes)
Enc_structure   83 67 456E6372797074 54 A2011818036E6D6572652E7061646C6F636B2F31 40
                = ["Encrypt", h'A201…2F31', h'']
```

### 3.3 Why slots change without touching the body

RFC 9052 §5.3 builds the content's associated data from context, protected and
external_aad, and for key-wrap recipients says: "recursively perform the encryption algorithm
for that recipient, using K (the encryption key) as the plaintext." The recipients are not an
input to the content AEAD, so adding or removing a slot needs only the CEK and leaves the
body's fields byte-identical [std]. Vectors V5 and V6 check this as bytes.

### 3.4 Slot identification (`kid`)

- Every slot MUST carry `kid` (label 4) in its unprotected bucket [profile]; RFC 9052 §8.5.2
  says the unprotected field "SHOULD contain a header parameter identifying the shared
  secret".
- Grammar [profile]: ASCII `<method>/<id>`, 3 to 64 bytes; `<method>` is `[a-z0-9]+`; `<id>`
  is one or more printable ASCII characters other than `/` and space (0x21 to 0x7E).
- `kid` MUST be unique within a container [profile]. The standard treats it as a hint
  (RFC 9052 §3.1: applications "MUST NOT assume" that `kid` values are unique, and "Key
  identifier values are hints about which key to use"); so does the
  reader when choosing slots, and the AES-KW integrity check is the truth.
- `kid` MUST NOT carry anything secret or personal [profile]: it is unprotected.
- **Methods and kinds.** `pass`: passphrase slot (§ 3.5). `dpapi`, `keychain`, `secsvc`: KEK
  slot (§ 3.6). Held for later (§ 3.7): `recov`, `fido`, `se`, `tpm`, `x25519`. A slot is a
  **profile slot** when its `alg` (either bucket) is A256KW (-5), it has no nested recipients,
  and its method names a kind this reader implements; every other slot is foreign (§ 5.4).

### 3.5 The passphrase slot

**Standard part.** An A256KW recipient [RFC 9053 §6.2.1, value -5]: protected empty
(RFC 9053 §6.2.1: "The protected header bucket MUST be empty"), unprotected `alg` and `kid`,
ciphertext = AES-KW(KEK, CEK), 40 bytes.

**Our sentence.** COSE has no password recipient: RFC 9052 §5.1.1 notes that "no password
algorithms have been defined", and the IANA COSE registries list no Argon2, scrypt or PBKDF2
entry (2026-11-13). So [profile, OP 4]:

> KEK = Argon2id(P = NFC(passphrase) as UTF-8, S = pl-kdf-salt, p = pl-kdf-p, T = 32,
> m = pl-kdf-m, t = pl-kdf-t, v = 0x13, K = empty, X = empty) [RFC 9106 §3.1 inputs]; the
> slot is then an ordinary A256KW recipient under that KEK.

The labels are private-use ("Integers less than -65536", IANA COSE Header Parameters); RFC
9052 §11.6: the "ranges tagged as private use are intended for testing purposes and closed
environments". The padlock file is a closed environment. They live in the **unprotected**
bucket because the protected bucket must be empty; so they cannot be marked `crit`
(RFC 9052 §3.1: when present, `crit` "MUST be placed in the
protected-header-parameters bucket"). A standard COSE reader sees an A256KW slot whose KEK it
does not have and can only fail.

| label | name | rule |
|---|---|---|
| -65537 | pl-kdf | MUST be 2, Argon2id (RFC 9106 §3.1, type y) [profile] |
| -65538 | pl-kdf-salt | MUST be 16 bytes, fresh from the OS RNG per slot write [profile]; RFC 9106 §4: "A length of 128 bits is sufficient for all applications" |
| -65539 | pl-kdf-m | KiB; MUST be within 65,536 to 1,048,576 (OP 5, OP 6), and ≥ 8·p [std: RFC 9106 §3.1] |
| -65540 | pl-kdf-t | MUST be within 3 to 16 (OP 5, OP 6) |
| -65541 | pl-kdf-p | MUST be within 4 to 16 (OP 5, OP 6; see the note in § 6 under OP 5) |
| -65542 | pl-kdf-v | MUST be 19 [std: RFC 9106 §3.1, "Version number v MUST be one byte 0x13"] |

All six MUST be present on a `pass` slot and no other label beyond `alg` and `kid`; none of
them may appear on a KEK slot [profile]. A writer's default is the floor, RFC 9106 §4's
second recommended option: "Argon2id with t=3 iterations, p=4 lanes, m=2^(16) (64 MiB of
RAM), 128-bit salt, and 256-bit tag size" (OP 5).

**Normalisation** [profile, OP 8]. The passphrase MUST be normalised to Unicode NFC before
Argon2id. This is the normalisation rule of RFC 8265's OpaqueString profile (§4.2.2, "Unicode
Normalization Form C (NFC) MUST be applied to all strings"), not the full profile: no width
mapping, no space mapping, no code-point refusal. A passphrase typed composed and decomposed
opens the same slot (vector V9). The vault's own passphrase file (`passphrase_root.rs`,
`passphrase_storage.rs`) MUST move to NFC in the same change that wires the padlock (phase
2), so the two never disagree on the same typed text; until then only the padlock normalises.

**The salt is not RFC 9053's `salt` (-20).** That label is an HKDF input (RFC 9053 §5.1) for
the algorithms in its Table 9; A256KW is not among them and Argon2 is not HKDF. Putting an
Argon2 salt under -20 would give a registered label an unregistered meaning.

**Why A256KW is sound here.** The CEK is 32 random bytes; RFC 9052 §8.5.2: "Key wrap mode is
considered to be superior to Direct Encryption if the system has any capability for doing
random-key generation." Its integrity check gives a clean wrong-passphrase signal: "If
unwrapping produces A[0] any other value, then the unwrap must return an error and not return
any key data" [RFC 3394 §2.2.3.1]. A wrong passphrase never reaches the content AEAD. A
passphrase change writes a fresh salt and so a fresh KEK, which RFC 9053 §6.2.1.1 asks for:
"The shared secret needs to have some method of being regularly updated over time."

### 3.6 The KEK slot (DPAPI, Keychain, Secret Service)

**Standard, entirely.** An A256KW recipient with `kid` [RFC 9053 §6.2.1; RFC 9052 §8.5.2].
The KEK is a random 32-byte key held by an OS store; only where it comes from is outside
COSE. Phase 1 implements the generic slot: the caller supplies the KEK.

| store | holds | `kid` | the KEK |
|---|---|---|---|
| Windows DPAPI (user scope, OP 11) | nothing: DPAPI is a function | `dpapi/<16 hex, random per slot>` | `CryptProtectData(KEK)` kept in the slot as `pl-os-blob` (-65543) |
| macOS Keychain | a data-protection generic-password item, the custodian's access group, `AccessibleWhenUnlockedThisDeviceOnly` | `keychain/<item account>` | the item's data |
| Linux Secret Service | an item naming the slot | `secsvc/<attribute value>` | the item's secret |

Rules [profile]:
- The OS store MUST hold a random 32-byte KEK, never the root and never the CEK, so the slot
  stays a standard A256KW recipient and removing the item never touches the root.
- A slot's KEK MUST NOT be reused for another slot or another container.
- `pl-os-blob` is opaque to the container, at most 2048 bytes (R15; phase 2 measures a real
  DPAPI blob and reports if that bound is too small). It is ciphertext under the OS's key; a
  tampered blob yields a different KEK, which fails the AES-KW check. It lives inside the
  slot so one file holds the whole padlock and removing the slot removes the blob.
- A missing item, a locked store or a DPAPI failure is "this slot cannot open", never a
  fallback and never a new root (custody D5: "Refuse; never write or read raw").
- Windows scope (OP 11): user-scope DPAPI first; a CNG key restricted to the custodian's
  virtual service account later, as a slot of the same shape with its own `kid` method.

### 3.7 Reserved slot kinds (later, not implemented)

Their numbers are held so they arrive as pure additions; a reader built now keeps such slots
as foreign (§ 5.4).
- **Recovery code**, method `recov`: a generated code shown once; its KDF is decided when the
  slot is built (OP 16).
- **Asymmetric**, methods `se`, `tpm`, `x25519`: ECDH-ES + A256KW (-31) [RFC 9053 §6.4.1], or
  COSE-HPKE if it is published first; Secure Enclave and TPM keys are P-256.
- **FIDO2 hmac-secret**, method `fido`: labels -65544 (credential ID) and -65545 (salt) held.
  Biometrics and device PINs are access gates on these keys, not slot kinds.

---

## 4. Operations

Every operation holds root, CEK, KEKs, passphrase bytes and Argon2 output in buffers cleared
on drop, and clears Argon2's working memory (vault lock ruling 33) [profile]. The phase 1 API
(`castellan::custody::padlock`) is data only: no file I/O, no OS calls.

### 4.1 Create (`Padlock::create`)

1. root := the given root. A migration MUST pass the existing root, never mint one [profile].
2. CEK := 32 bytes, IV := 12 bytes, salt := 16 bytes, all from the OS RNG [profile].
3. AAD := `["Encrypt", protected, h'']`; ciphertext := ChaCha20-Poly1305(CEK, IV, AAD, root)
   [std: RFC 9052 §5.3].
4. Add the first slot (§ 4.3 steps 3 to 5). The writer re-parses its own output under § 5
   before returning it [profile].

### 4.2 Unlock (`Padlock::unlock`)

1. Bound the file (R1) and decode it strictly (§ 5). Any structural fault refuses the whole
   file before any KDF, OS call or hardware prompt [profile].
2. Choose candidates: a passphrase is tried against every `pass` slot in file order; a KEK
   against the KEK slot whose `kid` the caller names. Foreign slots are never tried.
3. Derive each candidate's KEK (Argon2id with the slot's stored parameters, or the caller's
   KEK).
4. CEK := AES-KW-unwrap(KEK, wrapped). Failure means "not this slot" [std: RFC 3394 §2.2.3.1].
5. root := AEAD-decrypt(CEK, IV, AAD, ciphertext). A failure after a good unwrap means a
   damaged or forged body: refuse and try no other slot [profile].
6. **Binding check** [profile, OP 9]: the candidate root is accepted only if the caller's
   verifier accepts it. In the wallet (phase 2) the verifier opens the wallet's existing
   sealed records with it; a brand-new wallet has no record and so no check. Records are
   bound to their path by AEAD associated data, so a minted container's chosen root cannot
   open them.

### 4.3 Add a method (`Padlock::add_slot`)

1. Unlock (§ 4.2, including the binding check) through any one working slot, for the CEK.
2. Refuse a `kid` already present or a 17th slot [profile].
3. Build one A256KW recipient: a fresh salt (passphrase) or the caller's KEK and optional
   `pl-os-blob`; wrap the CEK; unwrap it again with the same KEK and compare [profile].
4. Append it. The body's protected bytes, IV and ciphertext, and every other slot (foreign
   ones included), MUST be unchanged byte for byte [profile; possible by § 3.3].
5. Re-parse the result under § 5; on failure the padlock is left as it was [profile].

### 4.4 Remove a method (`Padlock::remove_slot`)

Needs no key. Delete the slot named by `kid`. Refuse when no profile slot would remain: a
container left with only foreign slots cannot be opened by this reader [profile]. In phase 2,
an OS item is deleted only after the write that removed its slot succeeds. **This is not
revocation** (§ 1.3): an older copy of the file still opens with the removed method.

### 4.5 Rotate root (phase 2)

Rotation means **a new root**, offered as an explicit action beside removal (OP 13): a new
root, CEK and IV, every kept slot re-wrapped (every kept method present at once), and every
sealed record re-sealed under the new root in one transaction (custody constraints: "verify
the sealed reopen, then retire unsealed copies"). Only that changes what an old copy yields:
it then opens an obsolete root that opens only equally old records. A new CEK under the same
root buys nothing against old copies and is not offered.

### 4.6 Change passphrase

Add the new `pass` slot (fresh salt) and remove the old one before the single write [profile].
The old passphrase still opens older copies (§ 1.3).

### 4.7 File replacement and location (phase 2)

The file is `<data_root>/identity/wallet-root.padlock` (OP 15) [profile]. The writer:
verifies before writing (strict decode of the new bytes, the body decrypts to the root in
hand, an added slot unwraps to the CEK); writes through a same-directory temp file, fsync and
rename, on Windows too; reads back and repeats the checks, restoring the previous bytes on any
mismatch; and leaves no `.prev` or backup file on disk, which would be retained authority.

### 4.8 Migration (phase 2)

An explicit command (OP 15), in custody D5's style: load the existing root through its
current provider, create a padlock with **that** root and one OS slot of the platform (and a
passphrase slot if the user gives one), unlock through the new slot and reopen an existing
sealed record, and only then retire the old root file and store item. A failure leaves the
old file in place and no padlock file.

---

## 5. Strict decoding

The container is parsed before the user is authenticated, from a file anyone with write access
may have replaced. Every rule is checked before any Argon2 run, OS-store call or prompt
[profile]. Each rule has its own error (`PadlockError`) and at least one negative vector.

### 5.1 Rules

| # | rule | error | origin |
|---|---|---|---|
| R1 | file ≤ 16 KiB, checked before any parse | `TooLarge` | profile (OP 7) |
| R2 | exactly one well-formed CBOR item; nothing after it | `Malformed`, `TrailingBytes` | profile |
| R3 | tag 96 | `NotTagged` | profile; std RFC 9052 §5.1 defines it |
| R4 | deterministic encoding everywhere, inside protected bstrs too: definite lengths, shortest heads, map keys in bytewise order of their encodings | `NotDeterministic` | profile; std RFC 8949 §4.2.1 ("Preferred serialization MUST be used", "Indefinite-length items MUST NOT appear"); RFC 9052 §9 requires it only of the Enc_structure |
| R5 | no key twice in any map | `DuplicateLabel` | std RFC 9052 §9: "Applications MUST NOT parse and process messages with the same label used twice" |
| R6 | no label in both buckets of one layer | `LabelInBothBuckets` | profile (std SHOULD: RFC 9052 §3, "Applications SHOULD verify that the same label does not occur in both") |
| R7 | no `crit` in any layer | `Critical` | profile |
| R8 | COSE_Encrypt has 4 elements, a recipient 3 or 4 | `Structure` | std CDDL |
| R9 | 1 to 16 recipients | `NoSlots`, `TooManySlots` | std `[+COSE_recipient]`; profile bound (OP 7) |
| R10 | body protected exactly § 3.1's two entries; unprotected exactly the IV | `Version`, `WrongAlg`, `BodyHeader` | profile |
| R11 | IV 12 bytes; ciphertext 48 bytes | `IvLength`, `CiphertextLength` | profile; std RFC 9053 §4.3 |
| R12 | profile slot: protected is the zero-length bstr; only its kind's labels; wrapped CEK 40 bytes | `SlotProtected`, `SlotLabel`, `WrappedKeyLength` | std RFC 9053 §6.2.1 "MUST be empty"; profile refuses `h'A0'`, which RFC 9052 §3 says recipients "MUST accept", in its closed environment |
| R13 | `pass` slot: all six Argon2 labels; values within § 3.5's bounds; salt 16 bytes | `KdfLabels`, `KdfBounds`, `SaltLength` | profile; std RFC 9106 §3.1 for m ≥ 8p, v = 0x13 |
| R14 | every slot has a `kid` of § 3.4's grammar, unique in the file | `Kid`, `DuplicateKid` | profile |
| R15 | `pl-os-blob` a bstr of at most 2048 bytes | `OsBlob` | profile (OP 7) |
| R16 | text strings valid UTF-8 | `Malformed` | profile; std RFC 8949 |
| R17 | coset re-encodes the parsed structure to the input bytes | `NotDeterministic` | profile; Eidetic's re-encode equality |

R17 is what guarantees that a foreign slot is written back byte for byte: if coset re-emits the
whole file unchanged, it re-emits each slot unchanged.

### 5.2 What `coset` 0.4.2 enforces and what the reader adds

Read in the crate source (`~/.cargo/registry/.../coset-0.4.2`) and confirmed by the negative
vectors:

| check | coset | the reader |
|---|---|---|
| trailing bytes | refused (`ExtraneousData`) | mapped to `TrailingBytes` |
| tag | refuses a wrong tag | R3 checked on the decoded value first |
| array lengths | COSE_Encrypt 4; recipient 3 or 4 | nested recipients make a slot foreign |
| duplicate header labels | refused (`DuplicateMapKey`) | R5 checked on every map first, header or not |
| empty recipients | accepted | R9 |
| indefinite lengths, long heads | accepted silently | R4: the decoded value re-encoded must equal the input |
| map key order | `rest` labels kept in input order | R4: every map's keys sorted |
| protected bytes | kept as `original_data`, re-emitted unchanged | R4 inside each protected bstr; the body's compared to the fixed bytes |
| same label in both buckets, `crit` | not checked | R6, R7 |

### 5.3 Bounds

| bound | value | ruling |
|---|---|---|
| file | 16 KiB | OP 7 (driver default) |
| recipients | 16 | OP 7 (driver default) |
| `kid` | 3 to 64 bytes | profile |
| `pl-os-blob` | 2048 bytes | OP 7 (driver default) |
| Argon2 m | 65,536 to 1,048,576 KiB (64 MiB to 1 GiB) | OP 5 floor, OP 6 ceiling |
| Argon2 t | 3 to 16 | OP 5, OP 6 |
| Argon2 p | 4 to 16 | OP 5, OP 6 |

The file bound is checked on the byte length before decoding, so no length field inside the
file can drive an allocation beyond 16 KiB (a header claiming 2^64-1 bytes is `Malformed`,
tested). Argon2's memory is allocated only after R13 has passed.

### 5.4 Unknown slots: skip and keep

RFC 9052 §8.5.2: "Applications MUST deal with a recipient field being present that has an
unsupported algorithm. Failing to decrypt that specific recipient is an acceptable way of
dealing with it. Failing to process the message is not an acceptable way of dealing with it."
The profile applies this to its top-level slots [profile, OP 14]: a slot that passes R4 to R8
and R14 but is not a profile slot (§ 3.4) is foreign: never tried, counted toward R9, listed
by `slots()` as `Foreign`, and preserved byte for byte on every rewrite (V7). Structural
faults still refuse the whole file.

---

## 6. Decision record (custody D8)

The owner's rulings, in his words, 2026-11-14. Recorded as **custody D8** in the
[custody plan](2026-10-28_custody_plan.md).

**The design.** "use dpapi, keychain, secret service; wrap root with passphrase across all, so
you unlock (OS) a padlock (us). then we can do stuff like 2factor, pins, biometrics,
passphrases for that padlock". **A profile, not a format of our own:** "If one of these fits,
the slot file stops being 'our own format that needs our own spec and vectors' and becomes a
profile of a published standard with existing test vectors." **The container:**
"COSE_Encrypt". **Standing rules applied:** "We should remain strictly consumers, not forking
standards." (custody D6); own code in security domains needs "a spec and metrics to evaluate
by" (the vectors document states the metric and meets it); "Pure rust".

| OP | question | ruling (owner's words) | where |
|---|---|---|---|
| 1 | content algorithm | "ChaCha20-Poly1305" | § 3.2 |
| 2 | version header | "Protected content-type label": `"mere.padlock/1"`, label 3, protected | § 3.2 |
| 3 | tagged | tag 96 required. **Driver default**, told to the owner, not changed | § 3.2, R3 |
| 4 | passphrase slot | "AES key wrap + private Argon2 labels": A256KW (-5), Argon2id parameters in private labels in the unprotected bucket | § 3.5 |
| 5 | Argon2 cost | "RFC 9106's second set: 64 MiB, 3 passes, 4 lanes", the writer's default and the reader's floor | § 3.5, R13 |
| 6 | Argon2 ceiling | "1 GiB" memory; passes and lanes capped at 16 each | § 5.3 |
| 7 | size bounds | file 16 KiB, 16 recipients, OS blob 2048 bytes. **Driver default**; phase 2 measures a real DPAPI blob | § 5.3 |
| 8 | normalisation | "NFC, for vault and padlock together" | § 3.5 |
| 9 | root binding | "Existing sealed records must open"; a brand-new wallet has no check | § 4.2 step 6 |
| 10 | external_aad | empty. **Driver default** | § 3.2 |
| 11 | Windows slot | "User-scope DPAPI now, service-account key later" | § 3.6 |
| 12 | authenticate the slot list | "No: standard COSE only" | § 1.3 |
| 13 | rotation | "Explicit 'rotate root', offered with removal" | § 4.4, § 4.5 |
| 14 | unknown slots | "Skip it and keep it" | § 5.4 |
| 15 | migration; location | "An explicit command"; `<data_root>/identity/wallet-root.padlock` (location: **driver default**) | § 4.7, § 4.8 |
| 16 | recovery KDF | decided when that slot is built; reserved now. **Driver default** | § 3.7 |

**Note on OP 5's lane floor (open for the owner).** The ruling makes the whole second set the
reader's floor, so the reader refuses p < 4, and the code does. The draft's bounds table had p
from 1. Lanes set parallelism, not the attacker's cost (m and t do), so a lane floor buys no
strength; it only refuses a file a future writer might produce for a single-core device. The
choice between "p ≥ 4 as ruled" and "p ≥ 1" is the owner's.

---

## 7. What remains ours

Used as written: COSE_Encrypt and COSE_recipient, the Enc_structure, tag 96, the header
buckets, `alg`, `kid`, `IV`, `content type`; ChaCha20-Poly1305 content; A256KW recipients;
RFC 3394 AES-KW; RFC 9106 Argon2id; RFC 8949 deterministic encoding; Unicode NFC. Every
primitive is a library call on the family's lines: `coset` 0.4.2 on `ciborium` 0.2.2,
`chacha20poly1305` 0.11.0, `aes-kw` 0.3.1 on `aes` 0.9.4, `argon2` 0.6.0, `icu_normalizer`
2.4.0 (already in the graph through `idna`).

Ours, and therefore judged by our own vectors and the cross-check (vectors document § 4):
- the Argon2 sentence: six private labels, their values and bounds (`slot.rs`);
- the version string and the single allowed algorithm (`reader.rs::check_body`);
- slot identification: the `kid` grammar, uniqueness, method-to-kind mapping;
- the strict reader's additions over coset (§ 5.2);
- the container operations: create, unlock, add, remove, over coset, aes-kw and the AEAD;
- the NFC step's placement before Argon2id.
