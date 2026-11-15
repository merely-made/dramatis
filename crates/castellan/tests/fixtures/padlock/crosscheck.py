# Copyright 2026 Mark Alan Boykin
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# SPDX-License-Identifier: MPL-2.0
"""Second implementation of the padlock profile's vectors.

Written from design_docs/2026-11-14_padlock_profile.md and the RFCs, not from
the Rust code. Primitives come from `cryptography` (ChaCha20-Poly1305, AES key
wrap, Argon2id); the CBOR encoder below is written from RFC 8949 §3 and §4.2.1
and shares nothing with ciborium or coset.

    python -I crosscheck.py           # compare with vectors.json
    python -I crosscheck.py --write   # (re)write vectors.json

It first reproduces published vectors (positive controls); only then do its
own outputs count. Exit status 0 means every byte matched.
"""

import base64
import json
import os
import sys
import unicodedata

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors.json")


# --- CBOR (RFC 8949), deterministic unless told otherwise ------------------

class Tag:
    def __init__(self, n, item):
        self.n, self.item = n, item


class Map:
    """A map; `keep=True` keeps the given order and duplicates (negatives)."""

    def __init__(self, pairs, keep=False):
        self.pairs, self.keep = list(pairs), keep


class Raw:
    def __init__(self, data):
        self.data = data


class Indef(list):
    pass


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError(n)


def enc(x):
    if isinstance(x, Raw):
        return x.data
    if isinstance(x, bool) or x is None:
        raise TypeError(x)
    if isinstance(x, int):
        return head(0, x) if x >= 0 else head(1, -1 - x)
    if isinstance(x, (bytes, bytearray)):
        return head(2, len(x)) + bytes(x)
    if isinstance(x, str):
        b = x.encode("utf-8")
        return head(3, len(b)) + b
    if isinstance(x, Indef):
        return b"\x9f" + b"".join(enc(i) for i in x) + b"\xff"
    if isinstance(x, list):
        return head(4, len(x)) + b"".join(enc(i) for i in x)
    if isinstance(x, Map):
        items = [(enc(k), enc(v)) for k, v in x.pairs]
        if not x.keep:
            items.sort(key=lambda kv: kv[0])  # RFC 8949 §4.2.1 key order
        return head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(x, Tag):
        return head(6, x.n) + enc(x.item)
    raise TypeError(type(x))


def h(s):
    return bytes.fromhex(s.replace(" ", ""))


def seq(start, n):
    return bytes((start + i) & 0xFF for i in range(n))


def check(name, got, want):
    if got != want:
        sys.exit(f"MISMATCH {name}:\n got  {got.hex()}\n want {want.hex()}")
    print(f"ok  {name}")


# --- positive controls: published vectors ----------------------------------

def controls():
    # RFC 9106 5.3 Argon2id.
    kdf = Argon2id(salt=bytes([2]) * 16, length=32, iterations=3, lanes=4,
                   memory_cost=32, ad=bytes([4]) * 12, secret=bytes([3]) * 8)
    check("RFC 9106 5.3", kdf.derive(bytes([1]) * 32),
          h("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"))
    # RFC 3394 4.6: 256-bit key data with a 256-bit KEK.
    check("RFC 3394 4.6", aes_key_wrap(seq(0, 32), h(
        "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")),
        h("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"))
    # RFC 8439 2.8.2 AEAD_CHACHA20_POLY1305.
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
          b"only one tip for the future, sunscreen would be it.")
    out = ChaCha20Poly1305(seq(0x80, 32)).encrypt(
        h("070000004041424344454647"), pt, h("50515253c0c1c2c3c4c5c6c7"))
    check("RFC 8439 2.8.2", out, h(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
        "1ae10b594f09e26a7e902ecbd0600691"))
    # cose-wg Examples chacha-poly-examples/chacha-poly-01.json.
    prot = enc(Map([(1, 24)]))
    aad = enc(["Encrypt", prot, b""])
    check("chacha-poly-01 AAD", aad, h("8367456E637279707444A101181840"))
    cek = h("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100")
    iv = h("26682306D4FB28CA01B43B80")
    ct = ChaCha20Poly1305(cek).encrypt(iv, b"This is the content.", aad)
    rec = [b"", Map([(1, -6), (4, b"sec-256")]), b""]
    check("chacha-poly-01 message", enc(Tag(96, [prot, Map([(5, iv)]), ct, [rec]])), h(
        "D8608444A1011818A1054C26682306D4FB28CA01B43B8058241CD5D49DAA014CCAFFB30E765DC5CD"
        "410689AAE1C60B45648853298FF6808DB3FA8235DB818340A2012504477365632D32353640"))
    # cose-wg Examples aes-wrap-examples/aes-wrap-256-04.json.
    k = base64.urlsafe_b64decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg=")
    wrapped = h("DC4725A1E6FE212C3B2C268954C97E7422D4B85E6E131D72")
    cek = aes_key_unwrap(k, wrapped)
    check("aes-wrap-256-04 unwrap", cek, h("7A1B4CF7DCD2F9EC0F44B107B89BC7A5"))
    check("aes-wrap-256-04 wrap", aes_key_wrap(k, cek), wrapped)
    prot = enc(Map([(1, 1)]))
    aad = enc(["Encrypt", prot, b""])
    check("aes-wrap-256-04 AAD", aad, h("8367456E637279707443A1010140"))
    iv = h("DDDC08972DF9BE62855291A1")
    ct = AESGCM(cek).encrypt(iv, b"This is the content.", aad)
    rec = [b"", Map([(1, -5), (4, b"018c0ae5-4d9b-471b-bfd6-eef314bc7037")]), wrapped]
    check("aes-wrap-256-04 message", enc(Tag(96, [prot, Map([(5, iv)]), ct, [rec]])), h(
        "D8608443A10101A1054CDDDC08972DF9BE62855291A1582470C0A7FEEA2254DD2C301963DAF77580"
        "EE31F7C4125246D436EB205B58AEFB5140DFDF51818340A2012404582430313863306165352D3464"
        "39622D343731622D626664362D6565663331346263373033375818DC4725A1E6FE212C3B2C268954"
        "C97E7422D4B85E6E131D72"))


# --- the profile's own vectors ----------------------------------------------

ROOT, CEK, IV = seq(0x00, 32), seq(0x20, 32), seq(0x40, 12)
SALT, OS_KEK, OS_KEK2 = seq(0x50, 16), seq(0x60, 32), seq(0x80, 32)
SALT_NFC, OS_BLOB = seq(0xF0, 16), seq(0x00, 64)
PASSPHRASE = "correct horse battery staple"
NFC_COMPOSED = "Ångström café"
NFC_DECOMPOSED = unicodedata.normalize("NFD", NFC_COMPOSED)
M, T, P = 65536, 3, 4
KID_PASS, KID_OS = b"pass/1", b"keychain/test"
KID_NFC, KID_BLOB = b"pass/nfc", b"dpapi/0011223344556677"
KID_P1 = b"pass/p1"
FOREIGN = [b"", Map([(1, -65600), (4, b"foo/1")]), bytes(40)]


def argon(passphrase, salt, p=P):
    nfc = unicodedata.normalize("NFC", passphrase).encode("utf-8")
    return Argon2id(salt=salt, length=32, iterations=T, lanes=p,
                    memory_cost=M).derive(nfc)


def pass_unprot(kid, salt, extra=(), drop=(), m=M, t=T, p=P, v=19, kdf=2):
    pairs = [(1, -5), (4, kid), (-65537, kdf), (-65538, salt), (-65539, m),
             (-65540, t), (-65541, p), (-65542, v)]
    return Map([kv for kv in pairs if kv[0] not in drop] + list(extra))


def body(slots, prot=None, unprot=None, ct=None, tag=96):
    prot = enc(Map([(1, 24), (3, "mere.padlock/1")])) if prot is None else prot
    unprot = Map([(5, IV)]) if unprot is None else unprot
    arr = [prot, unprot, CIPHERTEXT if ct is None else ct, slots]
    return enc(Tag(tag, arr)) if tag is not None else enc(arr)


BODY_PROT = enc(Map([(1, 24), (3, "mere.padlock/1")]))
AAD = enc(["Encrypt", BODY_PROT, b""])
CIPHERTEXT = ChaCha20Poly1305(CEK).encrypt(IV, ROOT, AAD)


def vectors():
    kek_pass, kek_nfc = argon(PASSPHRASE, SALT), argon(NFC_DECOMPOSED, SALT_NFC)
    kek_p1 = argon(PASSPHRASE, SALT, p=1)
    wrap_p1 = aes_key_wrap(kek_p1, CEK)
    p1_slot = [b"", pass_unprot(KID_P1, SALT, p=1), wrap_p1]
    wrap_pass, wrap_os = aes_key_wrap(kek_pass, CEK), aes_key_wrap(OS_KEK, CEK)
    wrap_nfc, wrap_blob = aes_key_wrap(kek_nfc, CEK), aes_key_wrap(OS_KEK2, CEK)
    pass_slot = [b"", pass_unprot(KID_PASS, SALT), wrap_pass]
    os_slot = [b"", Map([(1, -5), (4, KID_OS)]), wrap_os]
    nfc_slot = [b"", pass_unprot(KID_NFC, SALT_NFC), wrap_nfc]
    blob_slot = [b"", Map([(1, -5), (4, KID_BLOB), (-65543, OS_BLOB)]), wrap_blob]
    nested = [b"", Map([(1, -5), (4, b"keychain/nested")]), wrap_os,
              [[b"", Map([(1, -6), (4, b"x/1")]), b""]]]
    steps = {
        "kek_pass": kek_pass, "kek_nfc": kek_nfc, "wrap_pass": wrap_pass,
        "wrap_os": wrap_os, "wrap_nfc": wrap_nfc, "wrap_blob": wrap_blob,
        "kek_p1": kek_p1, "wrap_p1": wrap_p1,
        "body_protected": BODY_PROT, "aad": AAD, "ciphertext": CIPHERTEXT,
    }
    containers = {
        "one_slot": body([pass_slot]),
        "two_slot": body([pass_slot, os_slot]),
        "os_only": body([os_slot]),
        "unknown_slot": body([pass_slot, os_slot, FOREIGN]),
        "unknown_slot_os_removed": body([pass_slot, FOREIGN]),
        "unknown_slot_os_readded": body([pass_slot, FOREIGN, os_slot]),
        "nested_foreign": body([pass_slot, nested]),
        "nfc_slot": body([nfc_slot]),
        "blob_slot": body([blob_slot]),
        "p1_slot": body([p1_slot]),
    }
    return steps, containers, negatives(pass_slot, os_slot, wrap_os)


def negatives(pass_slot, os_slot, wrap_os):
    two = body([pass_slot, os_slot])
    # The protected map with alg 24 written 19 0018 instead of 18 18.
    prot_nonmin = Raw(b"\x55\xa2\x01\x19\x00\x18" + BODY_PROT[4:])
    many = [[b"", Map([(1, -5), (4, f"keychain/{i}".encode())]), wrap_os] for i in range(17)]
    big_blob = [b"", Map([(1, -5), (4, KID_BLOB), (-65543, bytes(2049))]), wrap_os]

    def os_with(unprot, prot=b"", wrapped=wrap_os):
        return body([pass_slot, [prot, unprot, wrapped]])

    def pass_with(**kw):
        return body([[b"", pass_unprot(KID_PASS, kw.pop("salt", SALT), **kw), pass_slot[2]], os_slot])

    def bad_ct(text_bytes):
        m = head(5, 2) + enc(1) + enc(24) + enc(3) + head(3, len(text_bytes)) + text_bytes
        return body([pass_slot, os_slot], prot=m)

    n = {
        "too_large": ("R1", "TooLarge", two + bytes(16385 - len(two))),
        "truncated": ("R2", "Malformed", two[:-1]),
        "trailing": ("R2", "TrailingBytes", two + b"\x00"),
        "untagged": ("R3", "NotTagged", body([pass_slot, os_slot], tag=None)),
        "tag_16": ("R3", "NotTagged", body([pass_slot, os_slot], tag=16)),
        "indefinite_array": ("R4", "NotDeterministic", enc(Tag(96, Indef(
            [BODY_PROT, Map([(5, IV)]), CIPHERTEXT, [pass_slot, os_slot]])))),
        "nonminimal_int": ("R4", "NotDeterministic", pass_with(
            drop=(-65539,), extra=[(-65539, Raw(b"\x1b" + (65536).to_bytes(8, "big")))])),
        "nonminimal_protected": ("R4", "NotDeterministic", body([pass_slot, os_slot], prot=prot_nonmin)),
        "label_order": ("R4", "NotDeterministic", body([[b"", Map([
            (1, -5), (4, KID_PASS), (-65538, SALT), (-65537, 2), (-65539, M), (-65540, T),
            (-65541, P), (-65542, 19)], keep=True), pass_slot[2]], os_slot])),
        "duplicate_label": ("R5", "DuplicateLabel", os_with(
            Map([(1, -5), (4, KID_OS), (4, KID_OS)], keep=True))),
        "both_buckets": ("R6", "LabelInBothBuckets", body(
            [pass_slot, os_slot], unprot=Map([(1, 24), (5, IV)]))),
        "critical": ("R7", "Critical", body([pass_slot, os_slot], prot=enc(
            Map([(1, 24), (2, [-65599]), (3, "mere.padlock/1")])))),
        "fifth_element": ("R8", "Structure", enc(Tag(96, [
            BODY_PROT, Map([(5, IV)]), CIPHERTEXT, [pass_slot, os_slot], b""]))),
        "no_slots": ("R9", "NoSlots", body([])),
        "too_many_slots": ("R9", "TooManySlots", body(many)),
        "version_2": ("R10", "Version", body([pass_slot, os_slot], prot=enc(
            Map([(1, 24), (3, "mere.padlock/2")])))),
        "version_absent": ("R10", "Version", body([pass_slot, os_slot], prot=enc(Map([(1, 24)])))),
        "wrong_alg": ("R10", "WrongAlg", body([pass_slot, os_slot], prot=enc(
            Map([(1, 1), (3, "mere.padlock/1")])))),
        "body_extra_label": ("R10", "BodyHeader", body(
            [pass_slot, os_slot], unprot=Map([(4, b"x/1"), (5, IV)]))),
        "iv_11": ("R11", "IvLength", body([pass_slot, os_slot], unprot=Map([(5, IV[:11])]))),
        "ciphertext_47": ("R11", "CiphertextLength", body([pass_slot, os_slot], ct=CIPHERTEXT[:47])),
        "slot_protected": ("R12", "SlotProtected", os_with(Map([(4, KID_OS)]), prot=enc(Map([(1, -5)])))),
        "slot_label": ("R12", "SlotLabel", os_with(Map([(1, -5), (4, KID_OS), (-65538, SALT)]))),
        "wrapped_39": ("R12", "WrappedKeyLength", os_with(Map([(1, -5), (4, KID_OS)]), wrapped=wrap_os[:39])),
        "kdf_label_missing": ("R13", "KdfLabels", pass_with(drop=(-65542,))),
        "kdf_m_4gib": ("R13", "KdfBounds", pass_with(m=4194304)),
        "kdf_m_floor": ("R13", "KdfBounds", pass_with(m=32768)),
        "kdf_t_2": ("R13", "KdfBounds", pass_with(t=2)),
        "kdf_p_17": ("R13", "KdfBounds", pass_with(p=17)),
        "kdf_p_0": ("R13", "KdfBounds", pass_with(p=0)),
        "kdf_v_16": ("R13", "KdfBounds", pass_with(v=16)),
        "kdf_argon2i": ("R13", "KdfBounds", pass_with(kdf=1)),
        "salt_15": ("R13", "SaltLength", pass_with(salt=SALT[:15])),
        "kid_grammar": ("R14", "Kid", os_with(Map([(1, -5), (4, b"keychain")]))),
        "kid_absent": ("R14", "Kid", os_with(Map([(1, -5)]))),
        "duplicate_kid": ("R14", "DuplicateKid", os_with(Map([(1, -5), (4, KID_PASS)]))),
        "os_blob_2049": ("R15", "OsBlob", body([pass_slot, big_blob])),
        "invalid_utf8": ("R16", "Malformed", bad_ct(b"mere.padlock/\xff")),
    }
    return {k: {"rule": r, "error": e, "hex": b.hex()} for k, (r, e, b) in n.items()}


def main():
    controls()
    steps, containers, neg = vectors()
    doc = {
        "profile": "design_docs/2026-11-14_padlock_profile.md",
        "produced_by": "crosscheck.py (cryptography, own RFC 8949 encoder); "
                       "castellan padlock tests reproduce every positive entry",
        "inputs": {
            "root": ROOT.hex(), "cek": CEK.hex(), "iv": IV.hex(), "salt": SALT.hex(),
            "salt_nfc": SALT_NFC.hex(), "os_kek": OS_KEK.hex(), "os_kek2": OS_KEK2.hex(),
            "os_blob": OS_BLOB.hex(), "passphrase": PASSPHRASE,
            "nfc_composed_utf8": NFC_COMPOSED.encode().hex(),
            "nfc_decomposed_utf8": NFC_DECOMPOSED.encode().hex(),
            "argon2": {"m_kib": M, "t": T, "p": P},
        },
        "steps": {k: v.hex() for k, v in steps.items()},
        "containers": {k: v.hex() for k, v in containers.items()},
        "negatives": neg,
    }
    if "--write" in sys.argv:
        with open(VECTORS, "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
        print(f"wrote {VECTORS}")
        return
    with open(VECTORS, encoding="utf-8") as f:
        have = json.load(f)
    for section in ("inputs", "steps", "containers", "negatives"):
        if have[section] != doc[section]:
            for k in doc[section]:
                if have[section].get(k) != doc[section][k]:
                    print(f"MISMATCH {section}.{k}")
            sys.exit(1)
        print(f"ok  vectors.json {section}")


if __name__ == "__main__":
    main()
