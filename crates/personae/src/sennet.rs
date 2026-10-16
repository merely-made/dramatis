//! One wallet/device/realm's public Sennet node number. This is a scoped
//! identifier. Transient scoped material can additionally commission PKI;
//! the public number by itself authenticates neither RF nor a peer key.
use crate::{IdentityError, IdentityProvider};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const DOMAIN: &[u8] = b"mere.signalman.sennet.station/v1/";

fn valid_realm(realm: &[u8]) -> bool {
    !realm.is_empty()
        && realm.len() <= 128
        && realm
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Canonical custody namespace for one device UUID and application realm.
pub fn station_salt(device: &[u8; 16], realm: &str) -> Result<Vec<u8>, IdentityError> {
    if !valid_realm(realm.as_bytes()) {
        return Err(IdentityError::DerivationFailed(
            "invalid Sennet realm".into(),
        ));
    }
    let mut salt = Vec::with_capacity(DOMAIN.len() + 18 + realm.len());
    salt.extend_from_slice(DOMAIN);
    salt.extend_from_slice(device);
    salt.extend_from_slice(&(realm.len() as u16).to_le_bytes());
    salt.extend_from_slice(realm.as_bytes());
    Ok(salt)
}

/// Accept only a complete canonical station salt, without suffixes.
pub fn is_station_salt(salt: &[u8]) -> bool {
    let Some(body) = salt.strip_prefix(DOMAIN) else {
        return false;
    };
    body.len() >= 18
        && usize::from(u16::from_le_bytes([body[16], body[17]])) == body.len() - 18
        && valid_realm(&body[18..])
}

/// A public 32-bit node number. Truncation is not collision resistance:
/// the commissioning host must refuse a known peer with the same number.
#[derive(Debug, PartialEq, Eq)]
pub struct SennetStationIdentity {
    node_number: u32,
}
impl SennetStationIdentity {
    /// Derive from exactly the released device/realm child. No private bytes
    /// escape this method and no protocol or filesystem dependency is needed.
    pub fn derive(
        provider: &dyn IdentityProvider,
        device: &[u8; 16],
        realm: &str,
    ) -> Result<Self, IdentityError> {
        let child = provider.derive_keypair(&station_salt(device, realm)?)?;
        let public = child.public_key().to_bytes();
        let node_number = u32::from_le_bytes(public[..4].try_into().unwrap());
        if matches!(node_number, 0 | u32::MAX) {
            return Err(IdentityError::DerivationFailed(
                "reserved Sennet node number; commission another scope".into(),
            ));
        }
        Ok(Self { node_number })
    }
    /// Stable public sender number, without authenticating radio messages.
    pub fn node_number(&self) -> u32 {
        self.node_number
    }
}

/// Transient material for exactly one released Sennet device/realm child.
/// No master or sibling key is retained. Protocol-specific key construction
/// belongs to the protocol owner; never persist or log the returned bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SennetStationMaterial {
    seed: [u8; 32],
}
impl core::fmt::Debug for SennetStationMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SennetStationMaterial(<redacted>)")
    }
}
impl SennetStationMaterial {
    /// Derive only from the already admitted device/realm child.
    pub fn derive(
        provider: &dyn IdentityProvider,
        device: &[u8; 16],
        realm: &str,
    ) -> Result<Self, IdentityError> {
        let child = provider.derive_keypair(&station_salt(device, realm)?)?;
        Ok(Self {
            seed: child.to_seed(),
        })
    }
    /// Copy only for immediate typed protocol construction. The copy zeroizes
    /// when dropped, and this material zeroizes independently on drop.
    pub fn seed_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemoryProvider, RetainedKeys};

    #[test]
    fn stable_released_identity_is_confined_to_its_protocol_device_and_realm() {
        let wallet = InMemoryProvider::from_seed([19; 32]);
        let device = [7; 16];
        let salt = station_salt(&device, "ridge").unwrap();
        let released = RetainedKeys::capture(&wallet, std::slice::from_ref(&salt)).unwrap();
        let first = SennetStationIdentity::derive(&released, &device, "ridge").unwrap();
        assert_eq!(
            first,
            SennetStationIdentity::derive(&wallet, &device, "ridge").unwrap()
        );
        assert!(SennetStationIdentity::derive(&released, &[8; 16], "ridge").is_err());
        assert!(SennetStationIdentity::derive(&released, &device, "valley").is_err());
        assert!(released.derive_keypair(b"").is_err());
        assert!(
            released
                .derive_keypair(&crate::tucket::station_salt(&device, "ridge").unwrap())
                .is_err()
        );
        for foreign in crate::reticulum::station_salts(&device) {
            assert!(released.derive_keypair(&foreign).is_err());
        }
        assert_ne!(
            first,
            SennetStationIdentity::derive(&wallet, &[8; 16], "ridge").unwrap()
        );
        assert_ne!(
            first,
            SennetStationIdentity::derive(&wallet, &device, "valley").unwrap()
        );
    }

    #[test]
    fn release_parser_rejects_incomplete_extended_and_foreign_namespaces() {
        let salt = station_salt(&[1; 16], "radio-1").unwrap();
        assert!(is_station_salt(&salt));
        for end in 0..salt.len() {
            assert!(!is_station_salt(&salt[..end]));
        }
        let mut extra = salt.clone();
        extra.push(b'x');
        assert!(!is_station_salt(&extra));
        assert!(!is_station_salt(
            &crate::tucket::station_salt(&[1; 16], "radio-1").unwrap()
        ));
        for realm in ["", "a/b", "a\0b", "white space", "é"] {
            assert!(station_salt(&[1; 16], realm).is_err());
        }
        assert!(station_salt(&[1; 16], &"a".repeat(129)).is_err());
    }

    #[test]
    fn transient_material_is_same_child_without_broadening_release() {
        let wallet = InMemoryProvider::from_seed([19; 32]);
        let device = [7; 16];
        let salt = station_salt(&device, "ridge").unwrap();
        let released = RetainedKeys::capture(&wallet, std::slice::from_ref(&salt)).unwrap();
        let material = SennetStationMaterial::derive(&released, &device, "ridge").unwrap();
        let child = wallet.derive_keypair(&salt).unwrap();
        assert_eq!(*material.seed_bytes(), child.to_seed());
        assert_eq!(format!("{material:?}"), "SennetStationMaterial(<redacted>)");
        assert!(SennetStationMaterial::derive(&released, &[8; 16], "ridge").is_err());
        assert!(SennetStationMaterial::derive(&released, &device, "valley").is_err());
        assert_ne!(
            *material.seed_bytes(),
            *SennetStationMaterial::derive(&wallet, &[8; 16], "ridge")
                .unwrap()
                .seed_bytes()
        );
        assert_ne!(
            *material.seed_bytes(),
            *SennetStationMaterial::derive(&wallet, &device, "valley")
                .unwrap()
                .seed_bytes()
        );
        assert_eq!(
            SennetStationIdentity::derive(&released, &device, "ridge").unwrap(),
            SennetStationIdentity::derive(&wallet, &device, "ridge").unwrap()
        );
    }
}
