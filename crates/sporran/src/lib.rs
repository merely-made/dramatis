// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! A persona's wallet on disk.
//!
//! `personae::carry` is the wallet's model: record types, content refs and
//! derivation, with no filesystem, no policy and no seal seam. This crate is
//! the store adapter beside it: where the records live under a data root, how
//! they are written and read back, device grants and their pairing, revocation
//! and epoch material, the per-device settings, and the Muniment backend that
//! seals mutable slots under a wallet epoch (which implements eidetic's
//! `PayloadSealer`). It moved here from mere's `pandect` on 2026-11-03, so
//! that Castellan, which keeps secrets, links nothing from mere.

/// The wallet's epoch sealer: eidetic's `PayloadSealer` over a persona's private-epoch keys.
pub mod codicil_seal;
/// Per-device settings that live in the install-local data root.
pub mod device_settings_store;
/// Device grants, pairing, revocation and epoch material over the wallet store.
pub mod wallet_grant;
/// Wallet-sealed mutable slots over a caller-selected Muniment backend.
pub mod wallet_sealed_backend;
/// The wallet's files: paths, manifests, rosters and atomic writes.
pub mod wallet_store;

/// Narrow, expiring station grants over the public wallet records.
#[cfg(not(target_arch = "wasm32"))]
pub mod station_grant;

/// The directory under a data root that holds one folder per persona.
pub const PERSONAS_DIR: &str = "personas";

pub use device_settings_store::{
    DEVICE_SETTINGS_DIR, DEVICE_SETTINGS_FILENAME, DeviceSettings, MeshLendingSettings,
    QuietHoursSettings, StatedConditionSettings, device_settings_exist, device_settings_path,
    load_device_settings, save_device_settings,
};
pub use codicil_seal::WalletEpochSealer;
pub use wallet_sealed_backend::WalletSealedBackend;
pub use wallet_grant::{
    BlindedSlotId, DEVICE_GRANT_SCHEMA_VERSION, DeviceGrantError, EnrollmentBundleError,
    GrantStanding, PairedRemoteAuthGrantSpec, PairingCodeError, PairingMaterialError,
    PairingTicketError, PrivateEpochPlaintext, REMOTE_AUTH_ENROLLMENT_BUNDLE_SCHEMA_VERSION,
    REMOTE_AUTH_PAIRING_SAS_CONTEXT_V1, REMOTE_AUTH_PAIRING_SECRET_LEN,
    REMOTE_AUTH_PAIRING_TICKET_SCHEMA_VERSION, REMOTE_AUTH_PAIRING_WRAP_CONTEXT_V1,
    RemoteAuthEnrollmentBundle, RemoteAuthGrantSpec, RemoteAuthPairingMaterial,
    RemoteAuthPairingResponse, RemoteAuthPairingTicket, RemoteAuthPairingTicketRequest,
    WRAPPED_PRIVATE_EPOCH_FORMAT_V1, WrappedEpochError,
    WrappedEpochMaterial, WrappedEpochRecord, assess_device_grant, blinded_slot_id,
    build_remote_auth_enrollment_bundle, certificate_device_id, decode_device_grant_set,
    decode_epoch_record, decode_remote_auth_enrollment_bundle, decode_remote_auth_pairing_ticket,
    derive_remote_auth_pairing_material, device_grant_set_ref, device_is_fully_revoked,
    encode_device_grant_set, encode_epoch_record, encode_remote_auth_enrollment_bundle,
    encode_remote_auth_pairing_ticket, fold_revocations, format_remote_auth_pairing_code,
    load_device_grant_set, load_revocation_ledger, load_wrapped_epoch_record,
    mint_remote_auth_pairing_ticket, parse_remote_auth_pairing_code, requires_epoch_material,
    revoke_device_certificates, revoked_certificate_count, save_device_grant_set,
    save_wrapped_epoch_record, unwrap_private_epoch_material, wallet_trusted_roots,
    wrap_private_epoch_material,
};
pub use wallet_store::{
    CapabilitySlotRef, CarriagePolicy, DEVICE_ROSTER_FILENAME, DeviceExposure, DeviceGrantRef,
    DeviceMode, DevicePublicKey, DeviceRecord, DeviceRoster, IDENTITY_DIR,
    IDENTITY_GRANTS_DIR, IDENTITY_SEED_FILENAME, IDENTITY_WALLET_FILENAME, IdentityWalletManifest,
    KeyEpochId, LOCAL_DEVICE_IDENTITY_FILENAME, LocalDeviceIdentity, PERSONA_EPOCH_BRIDGE_FILENAME,
    PERSONA_WALLET_FILENAME, PersonaChainRoot, PersonaEpochBridge, PersonaWalletManifest,
    PersonaWalletRef, PrivateEpochRecord, PrivateRoots, PublicRoots,
    REMOTE_AUTH_WRAPPING_KEYS_FILENAME, RecoveryPolicy, RemoteAuthWrappingKeyBridge,
    RemoteAuthWrappingKeyRecord, WALLET_SCHEMA_VERSION, derive_persona_chain_root,
    device_grant_path, device_roster_path, device_roster_ref, identity_dir, identity_grants_dir,
    identity_seed_path, identity_wallet_path, load_device_grant, load_device_roster,
    load_identity_wallet, load_persona_wallet, local_device_identity_path,
    persona_epoch_bridge_path, persona_wallet_path, persona_wallet_salt,
    remote_auth_wrapping_keys_path, save_device_grant, save_device_roster, save_identity_wallet,
    save_persona_wallet,
};
