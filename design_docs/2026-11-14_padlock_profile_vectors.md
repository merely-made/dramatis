# The padlock profile: vectors, conformance and sources

**Date:** 2026-11-14
**Status:** companion to the [padlock profile](2026-11-14_padlock_profile.md) (custody D8),
split from it to keep each file under the repository's line ceiling. The vectors are
committed in `crates/castellan/tests/fixtures/padlock/vectors.json`; every positive entry is
produced by two implementations that share no code and agree byte for byte (§ 4).

The owner's rule for security code of our own is "a spec and metrics to evaluate by". The
metric here: **every cryptographic step passes a published vector, and every vector the
profile publishes is reproduced byte for byte by a second, independent implementation.**

---

## 1. Fixed inputs

All hex unless quoted. Chosen to be readable, not secret.

```
ROOT          000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
CEK           202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
IV            404142434445464748494A4B
SALT          505152535455565758595A5B5C5D5E5F
SALT_NFC      F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
OS_KEK        606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F
OS_KEK2       808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F
OS_BLOB       000102…3F (64 bytes, 00 to 3F)
PASSPHRASE    "correct horse battery staple"
NFC_COMPOSED  "Ångström café"  U+00C5 U+00F6 U+00E9   = C3856E67737472C3B66D20636166C3A9
NFC_DECOMP.   the same, NFD     A U+030A, o U+0308, e U+0301
                                = 41CC8A6E677374726FCC886D2063616665CC81
ARGON2        m = 65536 KiB, t = 3, p = 4, v = 0x13, T = 32, K = empty, X = empty
KIDS          "pass/1", "keychain/test", "pass/nfc", "dpapi/0011223344556677"
FOREIGN       [h'', {1: -65600, 4: "foo/1"}, h'00' × 40]
```

## 2. The profile's vectors

Keys are entries of `vectors.json` (`steps.*`, `containers.*`); tests are in
`crates/castellan/src/custody/padlock/tests_profile.rs`.

| id | what | inputs | expected (`vectors.json`) | test |
|---|---|---|---|---|
| V1 | Argon2id KEK | PASSPHRASE, SALT, ARGON2 | `steps.kek_pass` | `v1_v2_keks_and_wraps` |
| V2 | AES-KW of CEK under each KEK | CEK; V1; OS_KEK; OS_KEK2 | `steps.wrap_pass`, `wrap_os`, `wrap_blob` | `v1_v2_keks_and_wraps` |
| V3 | content AEAD | CEK, IV, AAD, ROOT | `steps.ciphertext` | `v3_v4_one_slot_container_and_unlock` |
| V4 | one-slot container (passphrase), and unlock | V1 to V3 | `containers.one_slot` | `v3_v4_one_slot_container_and_unlock` |
| V5 | add a KEK slot: before V4, after the two-slot container; body and first slot byte-identical | V4; OS_KEK | `containers.two_slot` | `v5_add_slot_keeps_body_and_first_slot` |
| V6 | remove the passphrase slot; body byte-identical; the last slot refuses removal | V5 | `containers.os_only` | `v6_remove_slot_keeps_body` |
| V7 | an unknown slot: opens, round-trips, survives remove and re-add of another slot byte for byte | V5 + FOREIGN | `containers.unknown_slot`, `unknown_slot_os_removed`, `unknown_slot_os_readded` | `v7_unknown_slot_opens_and_survives_rewrites` |
| V8 | an A256KW slot with nested recipients is foreign | V4 + nested | `containers.nested_foreign` | `v8_nested_recipients_make_a_slot_foreign` |
| V9 | NFC: written with the composed form, opened with the decomposed | NFC_*, SALT_NFC | `steps.kek_nfc`, `wrap_nfc`, `containers.nfc_slot` | `nfc_composed_and_decomposed_give_one_kek`, `v9_nfc_slot_opens_with_either_form` |
| V10 | KEK slot carrying an opaque OS blob | OS_KEK2, OS_BLOB | `containers.blob_slot` | `v10_kek_slot_with_os_blob` |
| V11 | one-lane passphrase slot at the floor (m 64 MiB, t 3, p 1; OP 5 as amended) | PASSPHRASE, SALT, kid `pass/p1` | `steps.kek_p1`, `wrap_p1`, `containers.p1_slot` | `v11_one_lane_slot_at_the_floor` |

Short values, for reading without the fixtures file:

```
kek_pass    F86A424FB40B0C968393BBC16D887B8A1061AEA961019B18F8BEF6988819FB17
kek_nfc     411D56F479026232ABD6EB1ECFF4854668408214D8A85C3A0A27278B5D88EB9A
wrap_pass   038E3670C82046BDAD18F710AEAE3A0A400BA107F10B79E58961745F7033846C3BF3303E8D596291
wrap_os     2A6C9B3F4263BEF5FC007D6298232D500BB378F81D76C755C79669316FDA0C4F0B80360CAFA13EFD
aad         8367456E637279707454A2011818036E6D6572652E7061646C6F636B2F3140
ciphertext  903495D643D477DD95FF105FFCA05D4B8D24822DFFE4E335B319EE0DBD5E8A13
            062D0A55C1CB1CC20B392161A9663CFD
```

The two-slot container (V5, 263 bytes):

```
D8608454A2011818036E6D6572652E7061646C6F636B2F31A1054C4041424344
45464748494A4B5830903495D643D477DD95FF105FFCA05D4B8D24822DFFE4E3
35B319EE0DBD5E8A13062D0A55C1CB1CC20B392161A9663CFD828340A8012404
46706173732F313A00010000023A0001000150505152535455565758595A5B5C
5D5E5F3A000100021A000100003A00010003033A00010004043A000100051358
28038E3670C82046BDAD18F710AEAE3A0A400BA107F10B79E58961745F703384
6C3BF3303E8D5962918340A20124044D6B6579636861696E2F7465737458282A
6C9B3F4263BEF5FC007D6298232D500BB378F81D76C755C79669316FDA0C4F0B
80360CAFA13EFD

96([h'A2011818036E6D6572652E7061646C6F636B2F31', {5: h'404142434445464748494A4B'},
    h'903495D6…63CFD',
    [[h'', {1: -5, 4: h'706173732F31', -65537: 2, -65538: h'5051…5F', -65539: 65536,
            -65540: 3, -65541: 4, -65542: 19}, h'038E3670…96291'],
     [h'', {1: -5, 4: h'6B6579636861696E2F74657374'}, h'2A6C9B3F…13EFD']]])
```

Not vectors yet: change passphrase and rotate root (phase 2 operations), and the reserved slot
kinds (their vectors come with them).

## 3. Negative vectors

`negatives.*` in `vectors.json`, each a mutation of the two-slot container (or of a slot in
it) with its rule and expected error; `every_negative_vector_is_refused_with_its_own_error`
parses each and asserts the error, and that R1 to R16 each have one. R17 has no vector of its
own: an input that passes R4 re-encodes identically through coset, so R17 is the guarantee
behind V7 rather than a separate refusal.

| rule | vectors (error) |
|---|---|
| R1 | `too_large`: 16,385 bytes (`TooLarge`) |
| R2 | `truncated` (`Malformed`); `trailing`: one byte after the item (`TrailingBytes`) |
| R3 | `untagged`; `tag_16` (`NotTagged`) |
| R4 | `indefinite_array`: `9F … FF`; `nonminimal_int`: m as `1B 0000000000010000`; `nonminimal_protected`: alg 24 as `19 0018` inside the protected bstr; `label_order`: -65538 before -65537 (`NotDeterministic`) |
| R5 | `duplicate_label`: `kid` twice in one slot (`DuplicateLabel`) |
| R6 | `both_buckets`: `alg` also in the body's unprotected bucket (`LabelInBothBuckets`) |
| R7 | `critical`: body protected gains `2: [-65599]` (`Critical`) |
| R8 | `fifth_element` (`Structure`) |
| R9 | `no_slots` (`NoSlots`); `too_many_slots`: 17 (`TooManySlots`) |
| R10 | `version_2`, `version_absent` (`Version`); `wrong_alg`: alg 1 (`WrongAlg`); `body_extra_label`: `kid` on the body (`BodyHeader`) |
| R11 | `iv_11` (`IvLength`); `ciphertext_47` (`CiphertextLength`) |
| R12 | `slot_protected`: `h'A10124'` (`SlotProtected`); `slot_label`: a salt on a KEK slot (`SlotLabel`); `wrapped_39` (`WrappedKeyLength`) |
| R13 | `kdf_label_missing` (`KdfLabels`); `kdf_m_4gib`, `kdf_m_floor` (32 MiB), `kdf_t_2`, `kdf_p_17`, `kdf_p_0`, `kdf_v_16`, `kdf_argon2i` (`KdfBounds`); `salt_15` (`SaltLength`) |
| R14 | `kid_grammar`, `kid_absent` (`Kid`); `duplicate_kid` (`DuplicateKid`) |
| R15 | `os_blob_2049` (`OsBlob`) |
| R16 | `invalid_utf8`: content type `mere.padlock/` + `FF` (`Malformed`) |

Also tested, outside the fixtures: a bstr header claiming 2^64-1 bytes is `Malformed` with no
allocation (`a_huge_length_claim_is_refused_without_allocating_it`); a wrong KEK or passphrase
is `WrongSecret` with no key data; a flipped body byte after a good unwrap is
`BodyAuthentication`; a verifier that refuses is `BindingRefused`; an input with no slot of
its kind is `NoMatchingSlot` (`unlock_failures`, `a_wrong_passphrase_returns_no_key`); the
writer refuses what the reader would (`the_writer_refuses_what_the_reader_would`).

## 4. The independent cross-check

`crates/castellan/tests/fixtures/padlock/crosscheck.py` is a second implementation written from
the profile and the RFCs, not from the Rust code. Its primitives are `cryptography`'s
(ChaCha20-Poly1305, AES key wrap, Argon2id); NFC is Python's `unicodedata`; the CBOR
encoder is its own, about forty lines written from RFC 8949 §3 and §4.2.1, sharing nothing
with ciborium or coset. It builds every COSE structure by hand.

```
python -I crates/castellan/tests/fixtures/padlock/crosscheck.py           # compare
python -I crates/castellan/tests/fixtures/padlock/crosscheck.py --write   # regenerate
```

It first reproduces the published vectors of § 5 (RFC 9106 §5.3, RFC 3394 §4.6, RFC 8439
§2.8.2, and both cose-wg examples whole, including aes-wrap-256-04's A128GCM content), so its
own outputs count only after its instrument is proved. Then it builds every vector of § 2 and
§ 3 and compares them with `vectors.json`; exit 0 means every byte matched.

**Result, 2026-11-14:** `vectors.json` was written by `crosscheck.py` (Python 3.11.14,
`cryptography` 50.0.0 on OpenSSL 4.0.1, `unicodedata` 14.0.0); the Rust tests rebuild every
positive entry from the fixed inputs through `castellan::custody::padlock` and match it byte
for byte, and the Rust reader refuses every negative entry with the error the script recorded.

**The CBOR encoder.** No CBOR library is installed on this machine (`cbor2` is absent), so the
script's encoder is its own rather than a library's. The driver accepted this on 2026-11-14:
it shares no code with ours, and it reproduces both cose-wg messages byte for byte. A
library-based variant would need `cbor2` installed.

## 5. Conformance table

Every cryptographic step, the published vector that exercises it, and the test.
`tests_published.rs` holds the published vectors as known answers; the cose-wg examples come
from the vendored checkout `Code/crates/cose-examples` at 53c9d634 (the GitHub head on
2026-11-14).

| step | published vector | how it is run | test |
|---|---|---|---|
| Argon2id v0x13 | RFC 9106 §5.3 (m 32 KiB, t 3, p 4, with K and X) | the `argon2` crate with the vector's secret and associated data | `rfc9106_argon2id` |
| AES-KW, 256-bit KEK over 256-bit key | RFC 3394 §4.6 | through the profile's own `wrap`/`unwrap`; a tampered wrap returns no key | `rfc3394_aes256_wrap_of_256_bit_key` |
| ChaCha20-Poly1305 | RFC 8439 §2.8.2 | the `chacha20poly1305` crate, nonce `07000000 ‖ IV` | `rfc8439_chacha20_poly1305` |
| Enc_structure and ChaCha20/Poly1305 content in COSE_Encrypt | cose-wg `chacha-poly-examples/chacha-poly-01.json` | whole: coset's AAD equals `AAD_hex`, decrypts to the plaintext, rebuilds the published bytes exactly (they are deterministic) | `cose_wg_chacha_poly_01` |
| A256KW as a COSE recipient | cose-wg `aes-wrap-examples/aes-wrap-256-04.json` | step by step: its CEK is 16 bytes (A128GCM content), so the unwrap and re-wrap are checked from its intermediates and the recipient's shape (empty protected, `alg` -5, `kid`) as structure; the message re-encodes to its bytes | `cose_wg_aes_wrap_256_04` |

Both cose-wg messages are refused by the padlock reader (`Version`: no content type), which the
tests assert: they are standard COSE but not this profile.

**What only our own vectors cover:**
- Argon2id **without** K and X at the profile's parameters (64 MiB, t 3, p 4): V1, V9,
  checked by the cross-check, since RFC 9106's only vector uses K and X at 32 KiB.
- A 32-byte CEK under a plain A256KW recipient inside COSE_Encrypt: no cose-wg example has one;
  RFC 3394 §4.6 covers the primitive, V2 to V5 the composition.
- More than one recipient on a COSE_Encrypt: no cose-wg COSE_Encrypt has two (the draft's
  survey); V5 to V8.
- The NFC step before Argon2id: V9.
- The private labels, the version string, the `kid` grammar, the strict reader (§ 3), add and
  remove leaving the body byte-identical (V5, V6), and foreign-slot preservation (V7, V8).

## 6. Sources

Read 2026-11-14. RFC texts were fetched as plain text from rfc-editor.org into scratch
(client name `cargo-check`) and every quote in the profile was searched for in them after
whitespace normalisation.

| ref | source | used for |
|---|---|---|
| RFC 9052 | https://www.rfc-editor.org/rfc/rfc9052.txt | §3, §3.1, §5.1, §5.1.1, §5.3, §8.5.2, §9, §11.6, §12 |
| RFC 9053 | https://www.rfc-editor.org/rfc/rfc9053.txt | §4.3, §4.3.1, §5.1, §6.2.1, §6.2.1.1, §6.4.1 |
| RFC 9106 | https://www.rfc-editor.org/rfc/rfc9106.txt | §3.1, §4, §5.3 |
| RFC 3394 | https://www.rfc-editor.org/rfc/rfc3394.txt | §2.2.3.1, §4.6 |
| RFC 8439 | https://www.rfc-editor.org/rfc/rfc8439.txt | §2.8.2 |
| RFC 8949 | https://www.rfc-editor.org/rfc/rfc8949.txt | §3, §4.2.1 |
| RFC 8265 | https://www.rfc-editor.org/rfc/rfc8265.txt | §4.2.2 |
| RFC 2119, 8174 | https://www.rfc-editor.org/rfc/rfc2119.txt, rfc8174.txt | key words |
| IANA COSE | https://www.iana.org/assignments/cose/cose.xml (updated 2026-11-13) | private-use ranges; algorithm values -5, 24, -31; no password KDF entry |
| cose-wg Examples | `Code/crates/cose-examples` @ 53c9d634 | § 5 |
| coset 0.4.2 | crate source in the cargo registry: `common/mod.rs`, `header/mod.rs`, `encrypt/mod.rs` | profile § 5.2 |
| aes-kw 0.3.1 | crate source: `kw.rs` (unwrap zeroes its output on failure) | profile § 3.5 |
| argon2 0.6.0, icu_normalizer 2.4.0 | crate source | `Params::new`, `hash_password_into_with_memory`; `ComposingNormalizerBorrowed::new_nfc().normalize_to` |
| draft and research | `Code/testing/engine-split/padlock_cose_profile_draft.md`, `research_padlock_container.md`, `research_unlock_pairing_totp.md`, `study_dramatis_stores_pairing_otp.md` | everything the profile carries over |
| Eidetic | origin/main `crates/eidetic-core/src/pack/envelope.rs`, `v2_cose_vectors.rs` | re-encode equality; known-answer layout |

## 7. Not verified

1. The real size of a DPAPI blob for a 32-byte input (phase 2 measures it against the 2048-byte
   bound).
2. `icu_normalizer`'s internal buffers: the NFC output is written into a pre-sized buffer that
   is cleared on drop, but the normaliser's own scratch storage is not ours to clear.
3. Unicode versions differ between the two implementations (Python's `unicodedata` 14.0, ICU4X
   2.4's data newer); the vectors use characters whose NFC is stable across both.
