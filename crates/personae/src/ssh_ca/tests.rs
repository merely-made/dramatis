// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::InMemoryProvider;
use crate::carry::{DeviceId, device_capability_scope};
use crate::delegation::Issue;
use crate::provider::AttestationKeys;
use insigne::delegation::{DelegationCertificate, DelegationParent};
use ssh_key::Algorithm;

const NOW_MS: u64 = 1_760_000_000_000;

fn device() -> DeviceId {
    DeviceId::from_uuid(uuid::Uuid::from_u128(0x2026_0812))
}

fn subject_key() -> PrivateKey {
    PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).unwrap()
}

fn grant_with(
    provider: &InMemoryProvider,
    actions: &[&str],
    expires_at_ms: Option<u64>,
) -> SignedDelegationCertificate {
    let master = provider.master_public_key().to_bytes();
    SignedDelegationCertificate::issue(
        provider,
        DelegationCertificate::new(
            DelegationParent::Root([7; 32]),
            master,
            master,
            device_capability_scope(device(), actions.iter().copied()),
            NOW_MS - 2000,
            NOW_MS - 1000,
            expires_at_ms,
            0,
            [4; 32],
        ),
    )
    .unwrap()
}

fn request<'a>(
    grant: &'a SignedDelegationCertificate,
    subject: &'a PublicKey,
    ledger: &'a crate::ssh_krl::RevocationLedger,
) -> UserCertRequest<'a> {
    UserCertRequest {
        grant,
        subject,
        principals: vec!["markik".into()],
        force_command: None,
        source_address: None,
        ledger,
    }
}

fn clean() -> crate::ssh_krl::RevocationLedger {
    crate::ssh_krl::RevocationLedger::new()
}

/// The plan's first validation: `ssh-key` 0.6 can mint and verify an
/// Ed25519 certificate, so the projection needs no new dependency.
#[test]
fn a_minted_certificate_validates_against_the_ca() {
    let provider = InMemoryProvider::from_seed([1; 32]);
    let ca = SshCertAuthority::derive(&provider).unwrap();
    let grant = grant_with(&provider, &[ACTION_SSH_LOGIN, ACTION_SSH_PTY], None);
    let subject = subject_key();
    let cert = ca
        .mint_user_cert(
            &request(&grant, &PublicKey::from(&subject), &clean()),
            NOW_MS,
        )
        .unwrap();

    assert!(cert.validate_at(NOW_MS / 1000, [&ca.fingerprint()]).is_ok());
    assert_eq!(cert.cert_type(), CertType::User);
    // A different CA must not validate it.
    let other = SshCertAuthority::derive(&InMemoryProvider::from_seed([9; 32])).unwrap();
    assert!(
        cert.validate_at(NOW_MS / 1000, [&other.fingerprint()])
            .is_err()
    );
}

/// The CA is a derived key like any other: same master, same CA.
#[test]
fn the_ca_key_is_deterministic_and_master_attested() {
    let provider = InMemoryProvider::from_seed([1; 32]);
    let first = SshCertAuthority::derive(&provider).unwrap();
    let second = SshCertAuthority::derive(&provider).unwrap();
    assert_eq!(first.fingerprint(), second.fingerprint());
    first
        .attestation()
        .check(&ssh_ca_salt())
        .expect("the CA key's attestation checks");
    assert_eq!(
        first.attestation().master_public_key().unwrap().to_bytes(),
        provider.master_public_key().to_bytes()
    );

    let other = SshCertAuthority::derive(&InMemoryProvider::from_seed([2; 32])).unwrap();
    assert_ne!(first.fingerprint(), other.fingerprint());
}

/// Actions the grant omits become extensions the certificate lacks.
#[test]
fn extensions_are_exactly_the_actions_the_grant_carries() {
    let provider = InMemoryProvider::from_seed([1; 32]);
    let ca = SshCertAuthority::derive(&provider).unwrap();
    let subject = PublicKey::from(&subject_key());

    let full = grant_with(
        &provider,
        &[
            ACTION_SSH_LOGIN,
            ACTION_SSH_PTY,
            ACTION_SSH_AGENT_FORWARD,
            ACTION_SSH_PORT_FORWARD,
        ],
        None,
    );
    let cert = ca
        .mint_user_cert(&request(&full, &subject, &clean()), NOW_MS)
        .unwrap();
    assert_eq!(cert.extensions().len(), 3);
    assert!(cert.extensions().contains_key("permit-pty"));

    let burner = grant_with(&provider, &[ACTION_SSH_LOGIN], None);
    let cert = ca
        .mint_user_cert(&request(&burner, &subject, &clean()), NOW_MS)
        .unwrap();
    assert!(
        cert.extensions().is_empty(),
        "a login-only grant permits nothing beyond the login"
    );
}

/// A certificate must never outlive the authority it projects.
#[test]
fn the_window_is_the_grant_intersected_with_the_ttl_ceiling() {
    let provider = InMemoryProvider::from_seed([1; 32]);
    let ca = SshCertAuthority::derive(&provider).unwrap();
    let subject = PublicKey::from(&subject_key());

    let short = grant_with(&provider, &[ACTION_SSH_LOGIN], Some(NOW_MS + 60_000));
    let cert = ca
        .mint_user_cert(&request(&short, &subject, &clean()), NOW_MS)
        .unwrap();
    assert_eq!(cert.valid_before(), (NOW_MS + 60_000) / 1000);

    let endless = grant_with(&provider, &[ACTION_SSH_LOGIN], None);
    let cert = ca
        .mint_user_cert(&request(&endless, &subject, &clean()), NOW_MS)
        .unwrap();
    assert_eq!(cert.valid_before(), (NOW_MS + MAX_CERT_TTL_MS) / 1000);
}

/// Every refusal the mint owes its caller, and the reason it owes it.
#[test]
fn minting_refuses_what_it_cannot_honestly_project() {
    let provider = InMemoryProvider::from_seed([1; 32]);
    let ca = SshCertAuthority::derive(&provider).unwrap();
    let subject = PublicKey::from(&subject_key());

    // No ssh.login: the grant is about some other device capability.
    let no_login = grant_with(&provider, &[crate::carry::ACTION_PRIVATE_READ], None);
    assert_eq!(
        ca.mint_user_cert(&request(&no_login, &subject, &clean()), NOW_MS),
        Err(CertMintError::NoLoginAction)
    );

    // Expired.
    let expired = grant_with(&provider, &[ACTION_SSH_LOGIN], Some(NOW_MS - 1));
    assert_eq!(
        ca.mint_user_cert(&request(&expired, &subject, &clean()), NOW_MS),
        Err(CertMintError::OutsideGrantWindow { at_ms: NOW_MS })
    );

    // Tampered: the check fails at the signature, so the projection never
    // begins.
    let mut tampered = grant_with(&provider, &[ACTION_SSH_LOGIN], None);
    tampered
        .certificate
        .scope
        .actions
        .insert(ACTION_SSH_PTY.into());
    assert_eq!(
        ca.mint_user_cert(&request(&tampered, &subject, &clean()), NOW_MS),
        Err(CertMintError::UnverifiedGrant(CheckFault::BadSignature))
    );

    // No principals is OpenSSH's "golden ticket": valid everywhere.
    let grant = grant_with(&provider, &[ACTION_SSH_LOGIN], None);
    let empty = clean();
    let mut bare = request(&grant, &subject, &empty);
    bare.principals.clear();
    assert_eq!(
        ca.mint_user_cert(&bare, NOW_MS),
        Err(CertMintError::NoPrincipals)
    );

    // A grant from another application's vocabulary.
    let mut foreign_cert = grant.certificate.clone();
    foreign_cert.scope.domain = "moot".into();
    let foreign = SignedDelegationCertificate::issue(&provider, foreign_cert).unwrap();
    assert_eq!(
        ca.mint_user_cert(&request(&foreign, &subject, &clean()), NOW_MS),
        Err(CertMintError::WrongDomain("moot".into()))
    );
}

/// The key id is the grant id, which is what makes revocation possible
/// without a second ledger.
#[test]
fn the_key_id_is_the_grant_id() {
    let provider = InMemoryProvider::from_seed([1; 32]);
    let ca = SshCertAuthority::derive(&provider).unwrap();
    let grant = grant_with(&provider, &[ACTION_SSH_LOGIN], None);
    let cert = ca
        .mint_user_cert(
            &request(&grant, &PublicKey::from(&subject_key()), &clean()),
            NOW_MS,
        )
        .unwrap();
    assert_eq!(cert.key_id(), key_id_for(&grant.certificate.id()));
    assert_eq!(cert.key_id().len(), 64);
}

#[test]
fn a_host_certificate_names_its_hostnames() {
    let provider = InMemoryProvider::from_seed([1; 32]);
    let ca = SshCertAuthority::derive(&provider).unwrap();
    let host = PublicKey::from(&subject_key());
    let cert = ca
        .mint_host_cert(
            &HostCertRequest {
                subject: &host,
                principals: vec!["q-pc.local".into(), "192.168.4.105".into()],
                valid_for_ms: 365 * 24 * 60 * 60 * 1000,
            },
            NOW_MS,
        )
        .unwrap();
    assert_eq!(cert.cert_type(), CertType::Host);
    assert!(cert.validate_at(NOW_MS / 1000, [&ca.fingerprint()]).is_ok());
    assert!(
        ca.known_hosts_ca_line("*.local")
            .unwrap()
            .starts_with("@cert-authority *.local ssh-ed25519 ")
    );
}

/// Known answers for what the CA puts on the wire: its `TrustedUserCAKeys`
/// line, its fingerprint, and a user and a host certificate minted from fixed
/// inputs. Ed25519 signing is deterministic, so the certificates are fixed
/// bytes. Recorded with ssh-key 0.6.7; an ssh-key move must leave them as is.
#[test]
fn ca_line_fingerprint_and_certificates_are_known_answers() {
    let provider = InMemoryProvider::from_seed([1; 32]);
    let ca = SshCertAuthority::derive(&provider).unwrap();
    let grant = grant_with(&provider, &[ACTION_SSH_LOGIN, ACTION_SSH_PTY], None);
    let subject = PublicKey::from(&PrivateKey::from(SshEd25519Keypair::from_seed(&[3; 32])));
    let user = ca
        .mint_user_cert(&request(&grant, &subject, &clean()), NOW_MS)
        .unwrap();
    let host = ca
        .mint_host_cert(
            &HostCertRequest {
                subject: &subject,
                principals: vec!["host.local".into()],
                valid_for_ms: 86_400_000,
            },
            NOW_MS,
        )
        .unwrap();
    let answers = [
        ca.trusted_user_ca_line().unwrap(),
        ca.fingerprint().to_string(),
        user.to_openssh().unwrap(),
        host.to_openssh().unwrap(),
    ];
    if std::env::var_os("PERSONAE_PRINT_ANSWERS").is_some() {
        for answer in &answers {
            eprintln!("ANSWER {answer}");
        }
    }
    assert_eq!(answers, CA_KNOWN_ANSWERS);
}

const CA_KNOWN_ANSWERS: [&str; 4] = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGF3znsnuhUTBse4lJI3XEcB0dBJlOz9oIp4WHOU8gND personae ssh certificate authority",
    "SHA256:VZetLMGxFAJ2nllNmdyLq0GrBtrG9ZcSpQk1VgRNYaA",
    "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAGG2TLqKe4WxaOfMnMm/P6oIAwCzImQEAAAAAACDtSSjGKNHCxurpAziQWZVhKVknOlxj+TY2wUYUrIc30QLqHA7dUlR2AAAAAQAAAEA2ZDkzMmVhMjllZTE2YzVhMzlmMzI3MzI2ZmNmZWE4MjJiNDY5M2IxZDllZDlkYWYzNjdhNzcwMGVkYzA5M2NjAAAACgAAAAZtYXJraWsAAAAAaOd4AAAAAABo6CDAAAAAAAAAABIAAAAKcGVybWl0LXB0eQAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBhd857J7oVEwbHuJSSN1xHAdHQSZTs/aCKeFhzlPIDQwAAAFMAAAALc3NoLWVkMjU1MTkAAABAJtN2145qn6wC/fQ3AXFmZLFwGpzux4bNZKlLks16+Keftf06Frx5DBrrAz0HIQ6Nu8KTVuE/hi6HroBUOK4ADA== personae",
    "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAEADALMiZAQAAAQAAAAAAAAAAAAAg7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9EAAAAAAAAAAAAAAAIAAAAYcGVyc29uYWUtaG9zdC1ob3N0LmxvY2FsAAAADgAAAApob3N0LmxvY2FsAAAAAGjneAAAAAAAaOjJgAAAAAAAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgYXfOeye6FRMGx7iUkjdcRwHR0EmU7P2ginhYc5TyA0MAAABTAAAAC3NzaC1lZDI1NTE5AAAAQL+H3KPua9lqSd5Eok7jM3unMWkcWwbdj8maBi+8oaMfJYuiDN6/+lUuxQiZCqQQCXI44trlbchN0lWdfXk63AU=",
];
