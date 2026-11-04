// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Owner's public-only SSH approval bridge and locally authenticated signer.
//! `relay` reads one bounded RemoteCommand and writes one RemoteReply. SSH
//! authenticates/pins the server; the custodian verifies the signed authority.
//! `inspect` returns only public identity. `sign PROFILE` signs one reviewed
//! delegation statement in the approval domain through native custody consent.

use std::io::{Read, Write};
use std::time::Duration;

use custody_wire::contract::{Answer, Outcome, Purpose};
use custody_wire::remote_approval::route::{RemoteCommand, RemoteReply};
use custody_wire::remote_approval::{DOMAIN, WEEK_SECONDS};
use custody_wire::secret::Bytes;
use custody_wire::{Client, Operation};
use dramatis_resident::custodian::InstalledCustodian;
use insigne::delegation::{
    DelegationCertificate, SignedDelegationCertificate, delegation_signing_salt,
};
use serde::{Serialize, de::DeserializeOwned};

#[path = "djinn-approval/statements.rs"]
mod statements;

const MAX_BYTES: u64 = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("djinn-approval: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["relay"] => {
            let command: RemoteCommand = input()?;
            let answer = call(&connect()?, Operation::RemoteApproval { command: Box::new(command) })?;
            let Answer::Value { value } = answer else { return Err("unexpected relay answer".into()); };
            // Decode again: an ordinary custody answer can never cross this route.
            let reply: RemoteReply = serde_json::from_value(value).map_err(|e| e.to_string())?;
            output(&reply)
        },
        ["inspect"] => {
            let client = connect()?;
            let snapshot = call(&client, Operation::Snapshot {})?;
            let wallet = call(&client, Operation::WalletPublic {})?;
            let Answer::Snapshot { snapshot } = snapshot else { return Err("unexpected identity answer".into()); };
            output(&serde_json::json!({"profiles": snapshot.profiles, "vault": snapshot.vault, "wallet": wallet}))
        },
        ["public", profile] => output(&call(&connect()?, Operation::PublicKey {
            source: custody_wire::contract::Source::Persona, profile: Some((*profile).into()),
        })?),
        ["sign", profile] => output(&sign(&connect()?, profile, input()?)?),
        ["enroll", profile, subject, seconds] => {
            let statement = statements::enrollment(input()?, subject, seconds)?;
            output(&sign(&connect()?, profile, statement)?)
        },
        ["approve", profile] => {
            let client = connect()?;
            let approval = statements::approval(&client, profile, input()?)?;
            output(&approval)
        },
        _ => Err("usage: djinn-approval relay | inspect | public PROFILE | sign PROFILE | enroll PROFILE SUBJECT_HEX SECONDS | approve PROFILE (public JSON on stdin)".into()),
    }
}

fn connect() -> Result<Client, String> {
    let installed = InstalledCustodian::load()?.ok_or("no installed custodian")?;
    #[cfg(unix)]
    let connector = custody_wire::transport::UnixSocketConnector::new(&installed.endpoint)
        .with_signed(installed.server.signed.clone());
    #[cfg(windows)]
    let connector = custody_wire::transport::NamedPipeConnector::new(&installed.endpoint);
    Client::open(&connector, &installed.server).map_err(|e| e.to_string())
}

fn call(client: &Client, operation: Operation) -> Result<Answer, String> {
    match client.call(operation, Duration::from_secs(150)) {
        Outcome::Success { answer } => Ok(answer),
        other => Err(format!("custodian did not complete: {other:?}")),
    }
}

fn sign(
    client: &Client,
    profile: &str,
    statement: DelegationCertificate,
) -> Result<SignedDelegationCertificate, String> {
    let expires = statement
        .expires_at_ms
        .ok_or("approval statements must expire")?;
    if statement.scope.domain != DOMAIN
        || !statement.is_well_formed()
        || expires.saturating_sub(statement.not_before_ms) > WEEK_SECONDS * 1000
    {
        return Err("not a finite custody approval statement".into());
    }
    // This is public and shown before custody asks for native authentication.
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&statement).map_err(|e| e.to_string())?
    );
    let answer = call(
        client,
        Operation::Sign {
            profile: profile.into(),
            purpose: Purpose::Delegation {
                audience: DOMAIN.into(),
            },
            salt: Bytes(delegation_signing_salt(&statement.scope)),
            message: Bytes(statement.signing_bytes()),
        },
    )?;
    let Answer::Signature {
        public_key,
        signature,
        attestation: Some(parts),
    } = answer
    else {
        return Err("missing custody signature or attestation".into());
    };
    if public_key != parts.derived || parts.master != statement.issuer {
        return Err("signer did not match statement".into());
    }
    let signer =
        insigne::DerivedKeyAttestation::from_parts(parts.master, parts.derived, parts.signature.0);
    let signed = SignedDelegationCertificate::from_parts(statement, signer, signature.to_vec());
    signed.check().map_err(|e| e.to_string())?;
    Ok(signed)
}

fn input<T: DeserializeOwned>() -> Result<T, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("public request exceeds route limit".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn output(value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("public reply exceeds route limit".into());
    }
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&bytes)
        .and_then(|()| stdout.write_all(b"\n"))
        .map_err(|e| e.to_string())
}
