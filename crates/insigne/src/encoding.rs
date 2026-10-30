// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The two text codecs keys travel in: base58btc (inside `did:key`) and hex
//! (a Reticulum identity).
//!
//! These adapters retain the formats and refusal behavior used by key types.

/// Encode bytes as base58btc. Each leading zero byte becomes a leading `1`.
pub(crate) fn base58_encode(bytes: &[u8]) -> String {
    bs58::encode(bytes)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string()
}

/// Decode base58btc, or `None` on a character outside the alphabet.
pub(crate) fn base58_decode(text: &str) -> Option<Vec<u8>> {
    bs58::decode(text)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .ok()
}

/// Lowercase hex, two characters per byte.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode exactly `N` bytes of hex, either case, or `None`.
pub(crate) fn hex_decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The examples published in the IETF base58 draft (draft-msporny-base58).
    const DRAFT_VECTORS: [(&[u8], &str); 3] = [
        (b"Hello World!", "2NEpo7TZRRrLZSi2U"),
        (
            b"The quick brown fox jumps over the lazy dog.",
            "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z",
        ),
        (&[0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd], "11233QC4"),
    ];

    #[test]
    fn base58_matches_the_draft_vectors_both_ways() {
        for (bytes, text) in DRAFT_VECTORS {
            assert_eq!(base58_encode(bytes), text);
            assert_eq!(base58_decode(text).as_deref(), Some(bytes));
        }
    }

    #[test]
    fn base58_keeps_leading_zeros_and_the_empty_string() {
        assert_eq!(base58_encode(&[]), "");
        assert_eq!(base58_encode(&[0]), "1");
        assert_eq!(base58_decode("11"), Some(vec![0, 0]));
        assert_eq!(base58_decode(""), Some(vec![]));
    }

    #[test]
    fn base58_refuses_characters_outside_the_alphabet() {
        for bad in ["0", "O", "I", "l", "+", "abc!"] {
            assert_eq!(base58_decode(bad), None, "{bad} is not base58btc");
        }
    }

    #[test]
    fn codecs_handle_empty_fixed_arrays_and_non_ascii_input() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_decode::<0>(""), Some([]));
        assert_eq!(hex_decode::<1>("é"), None);
        assert_eq!(base58_decode("é"), None);
        assert_eq!(base58_decode("1 1"), None);
    }

    #[test]
    fn hex_round_trips_and_reads_either_case() {
        let bytes = [0x00, 0x7f, 0xab, 0xff];
        assert_eq!(hex_encode(&bytes), "007fabff");
        assert_eq!(hex_decode::<4>("007FABff"), Some(bytes));
    }

    #[test]
    fn hex_refuses_wrong_length_and_bad_digits() {
        assert_eq!(hex_decode::<2>("abc"), None);
        assert_eq!(hex_decode::<2>("abcdef"), None);
        assert_eq!(hex_decode::<2>("zz00"), None);
    }
}
