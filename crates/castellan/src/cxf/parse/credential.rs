// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

pub(super) fn credential(
    ty: &str,
    original: &Value,
    normalized: &Value,
    raw: &str,
    title: &str,
    notice: &mut impl FnMut(&str),
) -> Result<(Option<PreparedCredential>, &'static str), ImportError> {
    let known = CXF_V1_TYPES.contains(&ty);
    let mut value = Json(normalized.clone());
    let mut quarantine = !known;
    let mut payload = None;
    let mut reference = None;
    let mut ssh = None;
    if ty == "passkey"
        && original
            .pointer("/fido2Extensions/hmacCredentials/algorithm")
            .and_then(Value::as_str)
            .is_some_and(|v| v != "hmac-sha256")
    {
        notice("unknown passkey HMAC algorithm ignored");
        return Ok((None, "ignored"));
    }
    if !known {
        notice("unknown credential type preserved verbatim in quarantine");
        return Ok((
            Some(PreparedCredential {
                kind: Some(CredentialKind::Unknown {
                    cxf_type: ty.into(),
                }),
                payload: Some(Payload::Secret {
                    bytes: raw.as_bytes().to_vec(),
                }),
                quarantine: true,
                reference: None,
                ssh: None,
            }),
            "quarantined",
        ));
    }
    // A known type can fall through the dependency's untagged Unknown arm.
    // Locally repair only the measured TOTP/custom-field gaps. Never call a
    // malformed known credential a newly introduced type.
    let typed: credential_exchange_format::Credential =
        serde_json::from_slice(raw.as_bytes()).map_err(|_| ImportError("invalid credential"))?;
    let malformed = matches!(
        &typed,
        credential_exchange_format::Credential::Unknown { .. }
    );
    typed.erase();
    if malformed && !matches!(ty, "totp" | "custom-fields") {
        notice("malformed known credential preserved in quarantine");
        return Ok((
            Some(PreparedCredential {
                kind: Some(empty_kind(ty)),
                payload: Some(Payload::Secret {
                    bytes: raw.as_bytes().to_vec(),
                }),
                quarantine: true,
                reference: None,
                ssh: None,
            }),
            "quarantined",
        ));
    }
    if ty == "custom-fields" {
        let Some(fields) = original["fields"].as_array() else {
            return malformed_known(ty, raw, notice);
        };
        let mut accepted = Vec::new();
        for field in fields {
            let Some(field_type) = field["fieldType"].as_str() else {
                return malformed_known(ty, raw, notice);
            };
            if ![
                "string",
                "concealed-string",
                "boolean",
                "date",
                "year-month",
                "subdivision-code",
                "country-code",
                "wifi-network-security-type",
                "email",
                "number",
            ]
            .contains(&field_type)
            {
                notice("unknown custom field type ignored");
                continue;
            }
            let encoded = Zeroizing::new(
                serde_json::to_vec(field).map_err(|_| ImportError("invalid custom field"))?,
            );
            match serde_json::from_slice::<credential_exchange_format::EditableFieldValue>(&encoded)
            {
                Ok(field) => {
                    let normalized = serde_json::to_value(&field);
                    field.erase();
                    accepted.push(normalized.map_err(|_| ImportError("invalid custom field"))?);
                },
                Err(_) => {
                    notice("invalid custom field value ignored");
                },
            }
        }
        std::mem::replace(
            &mut value.0,
            serde_json::json!({"type":ty,"label":text(original,"label"),"fields":accepted}),
        )
        .erase();
    }
    let kind = match ty {
        "address" => CredentialKind::Address,
        "person-name" => CredentialKind::PersonName,
        "note" => CredentialKind::Note,
        "generated-password" => CredentialKind::GeneratedPassword,
        "api-key" => CredentialKind::ApiKey {
            username: field(&value.0, "username"),
            key_type: field(&value.0, "keyType"),
            url: field(&value.0, "url"),
        },
        "basic-auth" => CredentialKind::BasicAuth {
            username: field(&value.0, "username"),
        },
        "credit-card" => {
            quarantine = true;
            let last = field(&value.0, "number").and_then(|mut number| {
                use zeroize::Zeroize;
                let digits: Zeroizing<String> =
                    Zeroizing::new(number.chars().filter(char::is_ascii_digit).collect());
                number.zeroize();
                digits
                    .get(digits.len().saturating_sub(4)..)
                    .and_then(|v| LastFour::parse(v).ok())
            });
            CredentialKind::CreditCard {
                card_type: field(&value.0, "cardType"),
                expiry: field(&value.0, "expiryDate").and_then(|v| YearMonth::parse(&v).ok()),
                last_four: last,
            }
        },
        "custom-fields" => CredentialKind::CustomFields {
            label: text(&value.0, "label"),
            field_labels: value.0["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| text(v, "label"))
                .collect(),
        },
        "drivers-license" => {
            quarantine = true;
            CredentialKind::DriversLicense {
                issuing_country: field(&value.0, "country")
                    .and_then(|v| CountryCode::parse(&v).ok()),
                territory: field(&value.0, "territory")
                    .and_then(|v| SubdivisionCode::parse(&v).ok()),
                expiry: field(&value.0, "expiryDate").and_then(|v| Date::parse(&v).ok()),
            }
        },
        "identity-document" => {
            quarantine = true;
            CredentialKind::IdentityDocument {
                issuing_country: field(&value.0, "issuingCountry")
                    .and_then(|v| CountryCode::parse(&v).ok()),
                expiry: field(&value.0, "expiryDate").and_then(|v| Date::parse(&v).ok()),
            }
        },
        "passport" => {
            quarantine = true;
            CredentialKind::Passport {
                passport_type: field(&value.0, "passportType"),
                issuing_country: field(&value.0, "issuingCountry")
                    .and_then(|v| CountryCode::parse(&v).ok()),
                expiry: field(&value.0, "expiryDate").and_then(|v| Date::parse(&v).ok()),
            }
        },
        "passkey" => {
            quarantine = true;
            CredentialKind::Passkey {
                rp_id: text(&value.0, "rpId").unwrap_or_default(),
                username: text(&value.0, "username").unwrap_or_default(),
                user_display_name: text(&value.0, "userDisplayName").unwrap_or_default(),
            }
        },
        "file" => {
            quarantine = true;
            let hash = decode64(text(&value.0, "integrityHash").as_deref().unwrap_or(""))?;
            let Ok(hash) = hash.as_slice().try_into() else {
                return malformed_known(ty, raw, notice);
            };
            CredentialKind::File {
                name: text(&value.0, "name").unwrap_or_default(),
                size: value.0["decryptedSize"].as_u64().unwrap_or_default(),
                integrity_hash: hash,
            }
        },
        "wifi" => CredentialKind::Wifi {
            ssid: field(&value.0, "ssid"),
            security: field(&value.0, "networkSecurityType")
                .and_then(|v| serde_json::from_value(Value::String(v)).ok()),
        },
        "item-reference" => {
            let target =
                text(&value.0["reference"], "item").ok_or(ImportError("invalid item reference"))?;
            source(&target)?;
            let account = text(&value.0["reference"], "account");
            if let Some(account) = &account {
                source(account)?;
            }
            reference = Some((account, target));
            return Ok((
                Some(PreparedCredential {
                    kind: None,
                    payload: None,
                    quarantine: false,
                    reference,
                    ssh: None,
                }),
                "link",
            ));
        },
        "totp" => {
            let Some(algorithm) = text(original, "algorithm") else {
                return malformed_known(ty, raw, notice);
            };
            let algorithm = match algorithm.as_str() {
                "sha1" => OtpAlgorithm::Sha1,
                "sha256" => OtpAlgorithm::Sha256,
                "sha512" => OtpAlgorithm::Sha512,
                _ => {
                    notice("unknown TOTP algorithm ignored");
                    return Ok((None, "ignored"));
                },
            };
            let Some(period) = original["period"]
                .as_u64()
                .filter(|v| (1..=65535).contains(v))
            else {
                return malformed_known(ty, raw, notice);
            };
            let Some(digits) = original["digits"].as_u64().filter(|v| *v <= 65535) else {
                return malformed_known(ty, raw, notice);
            };
            let Some(secret) = original["secret"].as_str() else {
                return malformed_known(ty, raw, notice);
            };
            let secret = match crate::otp::base32::decode(secret) {
                Ok(v) if !v.is_empty() => v,
                _ => {
                    notice("invalid base32 seed preserved in quarantine");
                    return malformed_known(ty, raw, notice);
                },
            };
            // Preserve unsupported counts in quarantine (ruling 68). They
            // must never reach the generator through credential exercise.
            if !(6..=10).contains(&digits) {
                quarantine = true;
                notice(&format!(
                    "unsupported OTP digit count {digits} preserved in quarantine"
                ));
            }
            let account = text(original, "username").unwrap_or_else(|| {
                notice("missing OTP username replaced by item title");
                title.into()
            });
            payload = Some(Payload::Otp {
                secret,
                counter: None,
            });
            CredentialKind::Otp {
                account,
                issuer: text(original, "issuer"),
                algorithm,
                code_style: OtpCodeStyle::Decimal {
                    digits: digits as u32,
                },
                mode: OtpMode::Totp { period, t0: 0 },
            }
        },
        "ssh-key" => {
            let key_type = text(&value.0, "keyType").ok_or(ImportError("missing SSH key type"))?;
            let der = decode64(text(&value.0, "privateKey").as_deref().unwrap_or(""))?;
            let comment = text(&value.0, "keyComment").unwrap_or_default();
            match super::super::ssh::decode(&key_type, &der, &comment) {
                Ok(private) => {
                    ssh = Some(private);
                },
                Err(_) => {
                    notice("SSH key refused: unsupported algorithm or invalid PKCS#8");
                    return Ok((None, "ignored"));
                },
            }
            return Ok((
                Some(PreparedCredential {
                    kind: None,
                    payload: None,
                    quarantine: false,
                    reference: None,
                    ssh,
                }),
                "ssh",
            ));
        },
        _ => return Err(ImportError("unhandled known CXF type")),
    };
    if payload.is_none() {
        payload = Some(Payload::Secret {
            bytes: serde_json::to_vec(&value.0)
                .map_err(|_| ImportError("cannot seal credential"))?,
        });
    }
    Ok((
        Some(PreparedCredential {
            kind: Some(kind),
            payload,
            quarantine,
            reference,
            ssh,
        }),
        if quarantine { "quarantined" } else { "stored" },
    ))
}
