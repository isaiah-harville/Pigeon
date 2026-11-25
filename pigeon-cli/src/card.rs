// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Contact cards, share links, and safety numbers, byte-compatible with the
//! iOS app so a terminal user and a phone user can add each other.
//!
//! A card is a `pigeon.wire.v1.ContactCard` (version 3): the identity bundle,
//! a display name, the relay URLs the owner reads, an Ed25519 signature over
//! those URLs (newline-joined), and the core-owned pairwise prekey bundle. It
//! travels as standard base64 (QR payload) or inside
//! `https://pigeonwire.app/contact#card=<base64url>`.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use pigeon_core::wire_proto;
use prost::Message;
use sha2::{Digest, Sha512};

const CARD_VERSION: u32 = 3;
const SHARE_PREFIX: &str = "https://pigeonwire.app/contact";
const MAX_RELAYS: usize = 8;
const MAX_RELAY_URL_LEN: usize = 2048;

/// A card that has passed every self-consistency check. Relay URLs are kept
/// only when the identity's signature over them verifies; otherwise the card
/// is honoured without them, exactly as the app does.
#[derive(Clone, Debug)]
pub struct VerifiedCard {
    pub identity: [u8; 32],
    pub name: String,
    pub relay_urls: Vec<String>,
    /// The pairwise control prekey bundle handed to `RegisterPairwiseContact`.
    pub prekey_bundle: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CardError {
    Encoding,
    Version,
    Identity,
    MissingPrekey,
}

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Encoding => "not a Pigeon contact card or link",
            Self::Version => "unsupported contact card version",
            Self::Identity => "contact card identity is malformed",
            Self::MissingPrekey => "contact card carries no prekey bound to its identity",
        })
    }
}

impl std::error::Error for CardError {}

/// The bytes an identity signs to vouch for its advertised relays.
pub fn relay_transcript(urls: &[String]) -> Vec<u8> {
    urls.join("\n").into_bytes()
}

/// Builds this device's card from the core snapshot's prekey bundle.
pub fn build(
    name: &str,
    prekey_bundle: &[u8],
    relay_urls: &[String],
    sign: impl Fn(&[u8]) -> [u8; 64],
) -> Result<Vec<u8>, CardError> {
    let bundle =
        wire_proto::PrekeyBundle::decode(prekey_bundle).map_err(|_| CardError::MissingPrekey)?;
    let relay_signature = if relay_urls.is_empty() {
        Vec::new()
    } else {
        sign(&relay_transcript(relay_urls)).to_vec()
    };
    Ok(wire_proto::ContactCard {
        version: CARD_VERSION,
        identity: bundle.identity,
        name: name.to_owned(),
        relay_urls: relay_urls.to_vec(),
        relay_signature,
        prekey_bundle: prekey_bundle.to_vec(),
        pairwise_control_prekey_bundle: prekey_bundle.to_vec(),
    }
    .encode_to_vec())
}

pub fn share_link(card: &[u8]) -> String {
    format!("{SHARE_PREFIX}#card={}", URL_SAFE_NO_PAD.encode(card))
}

pub fn qr_payload(card: &[u8]) -> String {
    STANDARD.encode(card)
}

/// Accepts a share link (fragment or legacy query form), a `pigeon://contact`
/// link, a bare base64 QR payload, or base64url.
pub fn decode_input(input: &str) -> Result<Vec<u8>, CardError> {
    let trimmed = input.trim();
    let payload = trimmed
        .split_once("#card=")
        .or_else(|| trimmed.split_once("?card="))
        .or_else(|| trimmed.split_once("&card="))
        .map_or(trimmed, |(_, value)| value);
    let payload = payload.split(['&', '#']).next().unwrap_or_default();
    let normalized: String = payload
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .filter(|c| *c != '=')
        .collect();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(normalized)
        .map_err(|_| CardError::Encoding)
}

pub fn verify(bytes: &[u8]) -> Result<VerifiedCard, CardError> {
    let card = wire_proto::ContactCard::decode(bytes).map_err(|_| CardError::Encoding)?;
    if card.version != CARD_VERSION {
        return Err(CardError::Version);
    }
    let identity_bundle = card.identity.ok_or(CardError::Identity)?;
    let identity: [u8; 32] = identity_bundle
        .identity_key
        .as_slice()
        .try_into()
        .map_err(|_| CardError::Identity)?;
    let verifying_key = VerifyingKey::from_bytes(&identity).map_err(|_| CardError::Identity)?;

    let relays_well_formed = card.relay_urls.len() <= MAX_RELAYS
        && card.relay_urls.iter().all(|url| is_valid_relay_url(url));
    let relays_signed = !card.relay_signature.is_empty()
        && <[u8; 64]>::try_from(card.relay_signature.as_slice())
            .map(|signature| {
                verifying_key
                    .verify_strict(
                        &relay_transcript(&card.relay_urls),
                        &Signature::from_bytes(&signature),
                    )
                    .is_ok()
            })
            .unwrap_or(false);
    let relay_urls = if relays_well_formed && relays_signed {
        card.relay_urls
    } else {
        Vec::new()
    };

    // Prefer the control prekey; fall back to the chat prekey for older cards.
    let prekey_bundle = [card.pairwise_control_prekey_bundle, card.prekey_bundle]
        .into_iter()
        .find(|encoded| bound_to(encoded, &identity))
        .ok_or(CardError::MissingPrekey)?;

    Ok(VerifiedCard {
        identity,
        name: sanitize_name(&card.name),
        relay_urls,
        prekey_bundle,
    })
}

fn bound_to(encoded: &[u8], identity: &[u8; 32]) -> bool {
    !encoded.is_empty()
        && wire_proto::PrekeyBundle::decode(encoded)
            .ok()
            .and_then(|bundle| bundle.identity)
            .is_some_and(|bundle| bundle.identity_key == identity)
}

pub fn is_valid_relay_url(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    url.len() <= MAX_RELAY_URL_LEN
        && matches!(scheme.to_ascii_lowercase().as_str(), "ws" | "wss")
        && !host.is_empty()
        && !host.contains('@')
        && !url.chars().any(char::is_whitespace)
}

/// Display names come from untrusted cards: strip control and bidi-override
/// characters so a name cannot rewrite the terminal or spoof another contact.
pub fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control() && !matches!(*c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'))
        .take(64)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "Unnamed".into()
    } else {
        trimmed.to_owned()
    }
}

/// Message text is untrusted: keep newlines and tabs, drop every other control
/// character (ANSI escapes) and bidi overrides before it reaches a terminal.
pub fn sanitize_message(text: &str) -> String {
    text.chars()
        .filter(|c| {
            (*c == '\n' || *c == '\t' || !c.is_control())
                && !matches!(*c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

/// Pigeon safety number, identical to the app's `SafetyNumber.compute`: each
/// key is iterated 5200 times through SHA-512 under a fixed context, the pair
/// is ordered so both sides agree, and the digests become 60 grouped digits.
pub fn safety_number(local: &[u8; 32], remote: &[u8; 32]) -> String {
    const CONTEXT: &[u8] = b"Pigeon.SafetyNumber.v1";
    fn iterated(key: &[u8; 32]) -> [u8; 64] {
        let mut current = [CONTEXT, key.as_slice()].concat();
        for _ in 0..5200 {
            let mut hasher = Sha512::new();
            hasher.update(&current);
            hasher.update(CONTEXT);
            hasher.update(key);
            current = hasher.finalize().to_vec();
        }
        current.try_into().unwrap()
    }
    fn digits(digest: &[u8; 64], count: usize) -> String {
        let mut out = String::new();
        let mut index = 0;
        while out.len() < count {
            let mut chunk: u64 = 0;
            for _ in 0..5 {
                chunk = (chunk << 8) | u64::from(digest[index]);
                index = (index + 1) % digest.len();
            }
            out.push_str(&format!("{:05}", chunk % 100_000));
        }
        out.truncate(count);
        out
    }
    let (first, second) = if local <= remote {
        (local, remote)
    } else {
        (remote, local)
    };
    let all = digits(&iterated(first), 30) + &digits(&iterated(second), 30);
    all.as_bytes()
        .chunks(5)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_every_share_form() {
        let card = b"\x08\x03 any bytes \xff\xfe".to_vec();
        for input in [
            share_link(&card),
            qr_payload(&card),
            URL_SAFE_NO_PAD.encode(&card),
            format!("pigeon://contact?card={}", URL_SAFE_NO_PAD.encode(&card)),
            format!("  {}\n", share_link(&card)),
        ] {
            assert_eq!(decode_input(&input).unwrap(), card, "{input}");
        }
        assert_eq!(decode_input("not base64 !!"), Err(CardError::Encoding));
    }

    #[test]
    fn relay_urls_are_validated() {
        assert!(is_valid_relay_url("wss://relay.pigeonwire.app/ws"));
        assert!(is_valid_relay_url("ws://127.0.0.1:8080/ws"));
        assert!(!is_valid_relay_url("https://relay.example/ws"));
        assert!(!is_valid_relay_url("wss://user@relay.example/ws"));
        assert!(!is_valid_relay_url("wss:///ws"));
    }

    #[test]
    fn names_cannot_carry_terminal_escapes() {
        assert_eq!(sanitize_name("\u{1b}[2JMallory\u{202E}"), "[2JMallory");
        assert_eq!(sanitize_name("   "), "Unnamed");
        assert_eq!(sanitize_message("a\u{1b}[31mb\nc\u{202E}"), "a[31mb\nc");
    }

    #[test]
    fn safety_number_is_symmetric_and_well_formed() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let number = safety_number(&a, &b);
        assert_eq!(number, safety_number(&b, &a));
        assert_eq!(number.len(), 60 + 11);
        assert!(number
            .split(' ')
            .all(|group| group.len() == 5 && group.chars().all(|c| c.is_ascii_digit())));
    }
}
