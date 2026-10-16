//! Scoped MeshCore station material. Custody stays in Djinn; the protocol
//! caller receives only one derived seed for one device and realm.
use std::fmt;

use crate::{IdentityError, IdentityProvider};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const DOMAIN: &[u8] = b"mere.signalman.tucket.station/v1/";

fn valid_realm(realm: &[u8]) -> bool {
    !realm.is_empty()
        && realm.len() <= 128
        && realm
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Canonical release salt for one durable device id and application realm.
pub fn station_salt(device: &[u8; 16], realm: &str) -> Result<Vec<u8>, IdentityError> {
    if !valid_realm(realm.as_bytes()) {
        return Err(IdentityError::DerivationFailed(
            "invalid Tucket realm".into(),
        ));
    }
    let mut salt = Vec::with_capacity(DOMAIN.len() + 18 + realm.len());
    salt.extend_from_slice(DOMAIN);
    salt.extend_from_slice(device);
    salt.extend_from_slice(&(realm.len() as u16).to_le_bytes());
    salt.extend_from_slice(realm.as_bytes());
    Ok(salt)
}

/// Recognize only complete canonical station salts for a release policy.
pub fn is_station_salt(salt: &[u8]) -> bool {
    let Some(body) = salt.strip_prefix(DOMAIN) else {
        return false;
    };
    if body.len() < 18 {
        return false;
    }
    let len = u16::from_le_bytes([body[16], body[17]]) as usize;
    len == body.len() - 18 && valid_realm(&body[18..])
}

/// Transient protocol seed, with redacted Debug and zeroization on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TucketStationMaterial {
    seed: [u8; 32],
}

impl fmt::Debug for TucketStationMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TucketStationMaterial(<redacted>)")
    }
}

impl TucketStationMaterial {
    /// Derive from an authority holding this commissioned scope.
    pub fn derive(
        provider: &dyn IdentityProvider,
        device: &[u8; 16],
        realm: &str,
    ) -> Result<Self, IdentityError> {
        let key = provider.derive_keypair(&station_salt(device, realm)?)?;
        Ok(Self {
            seed: key.to_seed(),
        })
    }

    /// Copy for immediate typed protocol construction. Never persist or log
    /// this material. The returned copy zeroizes when dropped.
    pub fn seed_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemoryProvider, RetainedKeys};

    #[test]
    fn scoped_release_is_stable_and_cannot_derive_other_scopes_or_protocols() {
        let wallet = InMemoryProvider::from_seed([19; 32]);
        let device = [7; 16];
        let salt = station_salt(&device, "ridge").unwrap();
        let released = RetainedKeys::capture(&wallet, std::slice::from_ref(&salt)).unwrap();
        let first = TucketStationMaterial::derive(&released, &device, "ridge").unwrap();
        let again = TucketStationMaterial::derive(&wallet, &device, "ridge").unwrap();
        assert_eq!(*first.seed_bytes(), *again.seed_bytes());
        assert!(TucketStationMaterial::derive(&released, &[8; 16], "ridge").is_err());
        assert!(TucketStationMaterial::derive(&released, &device, "valley").is_err());
        assert!(released.derive_keypair(b"").is_err());
        for foreign in crate::reticulum::station_salts(&device) {
            assert!(released.derive_keypair(&foreign).is_err());
            assert_ne!(salt, foreign);
        }
        for (other_device, realm) in [([8; 16], "ridge"), (device, "valley")] {
            let other = TucketStationMaterial::derive(&wallet, &other_device, realm).unwrap();
            assert_ne!(*first.seed_bytes(), *other.seed_bytes());
        }
        let other_wallet = InMemoryProvider::from_seed([20; 32]);
        let other = TucketStationMaterial::derive(&other_wallet, &device, "ridge").unwrap();
        assert_ne!(*first.seed_bytes(), *other.seed_bytes());
        assert_eq!(format!("{first:?}"), "TucketStationMaterial(<redacted>)");
    }

    #[test]
    fn release_parser_rejects_incomplete_or_extended_namespaces() {
        let salt = station_salt(&[1; 16], "radio-1").unwrap();
        assert!(is_station_salt(&salt));
        for end in 0..salt.len() {
            assert!(!is_station_salt(&salt[..end]));
        }
        let mut extra = salt.clone();
        extra.push(b'x');
        assert!(!is_station_salt(&extra));
        for realm in ["", "a/b", "a\0b", "white space", "\u{00e9}"] {
            assert!(station_salt(&[1; 16], realm).is_err());
        }
        assert!(station_salt(&[1; 16], &"a".repeat(129)).is_err());
    }
}
