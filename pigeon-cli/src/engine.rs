// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! The terminal client's messaging engine: `pigeon-core` plus the host-owned
//! state the app keeps beside it (contact names, relays, history).
//!
//! Every effect follows the same crash-safe order the iOS `SessionManager`
//! uses: core commits a transaction (sealed checkpoint), the host records what
//! it learned and seals its own state, and only then are the core's events
//! acknowledged and the relay's copy deleted. A crash between steps replays an
//! idempotent command instead of losing a message or reusing a ratchet index.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use pigeon_core::{wire_proto as proto, ClientCommand, Error as CoreError, PigeonClient};
use pigeon_mesh::{EnvelopeType, MeshPacket, SessionEnvelope};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::card::{self, VerifiedCard};
use crate::identity::{CliIdentity, SealedCheckpointStore};
use crate::vault::{Vault, VaultError};

const APP_LABEL: &str = "app";
const COMMAND_VERSION: u32 = 1;
const MAX_HISTORY_PER_CONTACT: usize = 2_000;

#[derive(Debug)]
pub enum EngineError {
    Vault(VaultError),
    Core(CoreError),
    Card(card::CardError),
    UnknownContact(String),
    Ambiguous(String),
    NotAllowed(&'static str),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vault(error) => write!(f, "{error}"),
            Self::Core(error) => write!(f, "{error}"),
            Self::Card(error) => write!(f, "{error}"),
            Self::UnknownContact(name) => write!(f, "no contact matches \"{name}\""),
            Self::Ambiguous(name) => write!(f, "\"{name}\" matches more than one contact"),
            Self::NotAllowed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<VaultError> for EngineError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

impl From<CoreError> for EngineError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

impl From<card::CardError> for EngineError {
    fn from(error: card::CardError) -> Self {
        Self::Card(error)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Relationship {
    Contact,
    OutgoingRequest,
    IncomingRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub identity: String,
    pub name: String,
    pub relays: Vec<String>,
    pub relationship: Relationship,
    #[serde(default)]
    pub verified: bool,
}

impl Contact {
    pub fn identity_bytes(&self) -> [u8; 32] {
        hex::decode(&self.identity)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .unwrap_or([0; 32])
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Delivery {
    Sent,
    Delivered,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub mine: bool,
    pub text: String,
    pub at_ms: i64,
    #[serde(default)]
    pub delivery: Option<Delivery>,
    #[serde(default)]
    pub system: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct AppState {
    name: String,
    relays: Vec<String>,
    contacts: Vec<Contact>,
    history: BTreeMap<String, Vec<HistoryEntry>>,
}

/// Something the user should see, produced while absorbing core events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    Message { from: String, text: String },
    Request { from: String, text: String },
    Delivered { to: String },
    Accepted { by: String },
    System { from: String, text: String },
}

/// How the transport should treat the relay's copy of an inbound envelope.
#[derive(Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Durably applied (or permanently unusable): delete it from the relay.
    Consumed,
    /// A local failure that may clear: keep the relay copy for redelivery.
    Retry,
}

/// A pairwise ciphertext the core wants deposited on a recipient's relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub item_id: String,
    pub relay_url: String,
    pub recipient: [u8; 32],
    /// The relay `ciphertext` field: a one-hop mesh packet around the session
    /// envelope, base64-encoded, exactly as the iOS app deposits it.
    pub frame: String,
}

pub struct Engine {
    vault: Arc<Vault>,
    identity: CliIdentity,
    client: PigeonClient<SealedCheckpointStore, CliIdentity>,
    app: AppState,
}

impl Engine {
    /// Creates a new identity in an empty vault.
    pub fn create(vault: Vault, name: &str, relays: Vec<String>) -> Result<Self, EngineError> {
        let vault = Arc::new(vault);
        let identity = CliIdentity::create(&vault)?;
        let app = AppState {
            name: card::sanitize_name(name),
            relays,
            ..AppState::default()
        };
        let mut engine = Self::assemble(vault, identity, app)?;
        engine.save()?;
        engine.execute(ClientCommand::ensure_pairwise_account(
            "ensure-pairwise-account",
        )?)?;
        Ok(engine)
    }

    pub fn open(vault: Vault) -> Result<Self, EngineError> {
        let vault = Arc::new(vault);
        let identity = CliIdentity::load(&vault)?;
        let app = match vault.load(APP_LABEL)? {
            Some(bytes) => {
                serde_json::from_slice(&bytes).map_err(|_| VaultError::Corrupt("app state"))?
            }
            None => AppState::default(),
        };
        let mut engine = Self::assemble(vault, identity, app)?;
        engine.execute(ClientCommand::ensure_pairwise_account(
            "ensure-pairwise-account",
        )?)?;
        // Events committed before a crash are re-absorbed (idempotently).
        engine.absorb_pending_events()?;
        Ok(engine)
    }

    fn assemble(
        vault: Arc<Vault>,
        identity: CliIdentity,
        app: AppState,
    ) -> Result<Self, EngineError> {
        let client =
            PigeonClient::new(SealedCheckpointStore::new(vault.clone()), identity.clone())?;
        Ok(Self {
            vault,
            identity,
            client,
            app,
        })
    }

    // MARK: - Identity and contacts

    pub fn public_identity(&self) -> [u8; 32] {
        self.identity.public()
    }

    /// Signs a relay mailbox challenge with the root identity key, which is
    /// also the mailbox address (the app's `RelayTransport` does the same).
    pub fn sign_relay_challenge(&self, nonce: &[u8]) -> [u8; 64] {
        self.identity.sign(nonce)
    }

    pub fn name(&self) -> &str {
        &self.app.name
    }

    pub fn relays(&self) -> &[String] {
        &self.app.relays
    }

    pub fn set_relays(&mut self, relays: Vec<String>) -> Result<(), EngineError> {
        if !relays.iter().all(|url| card::is_valid_relay_url(url)) {
            return Err(EngineError::NotAllowed(
                "relay URLs must be ws:// or wss://",
            ));
        }
        self.app.relays = relays;
        self.save()
    }

    pub fn contacts(&self) -> &[Contact] {
        &self.app.contacts
    }

    pub fn card(&self) -> Result<Vec<u8>, EngineError> {
        let prekey = self.snapshot()?.pairwise_prekey_bundle;
        Ok(card::build(
            &self.app.name,
            &prekey,
            &self.app.relays,
            |message| self.identity.sign(message),
        )?)
    }

    pub fn safety_number(&self, contact: &Contact) -> String {
        card::safety_number(&self.public_identity(), &contact.identity_bytes())
    }

    /// Adds a contact from a card. `mutual` means both sides added each other
    /// in person (QR swap) and can message freely; otherwise this is a
    /// message request the other side must accept.
    pub fn add_contact(&mut self, input: &str, mutual: bool) -> Result<Contact, EngineError> {
        let verified = card::verify(&card::decode_input(input)?)?;
        if verified.identity == self.public_identity() {
            return Err(EngineError::NotAllowed("that is your own card"));
        }
        if let Some(existing) = self.find_by_identity(&verified.identity) {
            return Ok(existing.clone());
        }
        let relationship = if mutual {
            Relationship::Contact
        } else {
            Relationship::OutgoingRequest
        };
        self.register_in_core(&verified, relationship)?;
        let contact = Contact {
            identity: hex::encode(verified.identity),
            name: verified.name,
            relays: verified.relay_urls,
            relationship,
            verified: mutual,
        };
        self.app.contacts.push(contact.clone());
        self.save()?;
        Ok(contact)
    }

    fn register_in_core(
        &mut self,
        card: &VerifiedCard,
        relationship: Relationship,
    ) -> Result<(), EngineError> {
        let relay_url = card.relay_urls.first().cloned().unwrap_or_default();
        let digest = Sha256::new()
            .chain_update(card.identity)
            .chain_update(&card.prekey_bundle)
            .chain_update(relay_url.as_bytes())
            .finalize();
        self.execute_proto(
            format!("register-pairwise-contact:{}", hex::encode(digest)),
            proto::client_command::Body::RegisterPairwiseContact(proto::RegisterPairwiseContact {
                prekey_bundle: card.prekey_bundle.clone(),
                relay_url,
                relationship: match relationship {
                    Relationship::Contact => proto::PairwiseRelationship::Contact,
                    Relationship::OutgoingRequest => proto::PairwiseRelationship::OutgoingRequest,
                    Relationship::IncomingRequest => proto::PairwiseRelationship::IncomingRequest,
                } as i32,
            }),
        )?;
        Ok(())
    }

    /// Resolves a contact by name prefix (case-insensitive) or identity hex prefix.
    pub fn resolve(&self, query: &str) -> Result<Contact, EngineError> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return Err(EngineError::UnknownContact(query.into()));
        }
        let exact: Vec<_> = self
            .app
            .contacts
            .iter()
            .filter(|contact| contact.name.to_lowercase() == needle)
            .collect();
        let candidates: Vec<_> = if exact.is_empty() {
            self.app
                .contacts
                .iter()
                .filter(|contact| {
                    contact.name.to_lowercase().starts_with(&needle)
                        || (needle.len() >= 6 && contact.identity.starts_with(&needle))
                })
                .collect()
        } else {
            exact
        };
        match candidates.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(EngineError::UnknownContact(query.into())),
            _ => Err(EngineError::Ambiguous(query.into())),
        }
    }

    pub fn mark_verified(&mut self, identity: &str) -> Result<(), EngineError> {
        if let Some(contact) = self.contact_mut(identity) {
            contact.verified = true;
        }
        self.save()
    }

    pub fn rename(&mut self, identity: &str, name: &str) -> Result<(), EngineError> {
        if let Some(contact) = self.contact_mut(identity) {
            contact.name = card::sanitize_name(name);
        }
        self.save()
    }

    pub fn history(&self, identity: &str) -> &[HistoryEntry] {
        self.app.history.get(identity).map_or(&[], Vec::as_slice)
    }

    // MARK: - Sending

    pub fn send_text(&mut self, contact: &Contact, text: &str) -> Result<String, EngineError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(EngineError::NotAllowed("message is empty"));
        }
        if text.len() > pigeon_core::MAX_DIRECT_MESSAGE_BYTES / 2 {
            return Err(EngineError::NotAllowed("message is too long"));
        }
        let current = self
            .find_by_identity(&contact.identity_bytes())
            .cloned()
            .ok_or_else(|| EngineError::UnknownContact(contact.name.clone()))?;
        match current.relationship {
            Relationship::IncomingRequest => {
                return Err(EngineError::NotAllowed(
                    "accept this message request before replying (`accept <name>`)",
                ))
            }
            Relationship::OutgoingRequest
                if self
                    .history(&current.identity)
                    .iter()
                    .any(|entry| entry.mine && !entry.system) =>
            {
                return Err(EngineError::NotAllowed(
                    "you sent an introduction; you can send more after they accept",
                ))
            }
            _ => {}
        }
        let id = new_uuid();
        let now = now_ms();
        let sender_contact_card = if current.relationship == Relationship::OutgoingRequest {
            self.card()?
        } else {
            Vec::new()
        };
        self.send_application(
            &current,
            proto::DirectApplication {
                application_id: id.clone(),
                body: Some(proto::direct_application::Body::Message(
                    proto::DirectMessage {
                        text: text.to_owned(),
                        reply_snippet: String::new(),
                        sender_timestamp_ms: now,
                    },
                )),
            },
            sender_contact_card,
        )?;
        self.record(
            &current.identity,
            HistoryEntry {
                id: id.clone(),
                mine: true,
                text: text.to_owned(),
                at_ms: now,
                delivery: Some(Delivery::Sent),
                system: false,
            },
        )?;
        Ok(id)
    }

    /// Accepts an incoming message request and tells the requester.
    pub fn accept(&mut self, contact: &Contact) -> Result<(), EngineError> {
        if contact.relationship != Relationship::IncomingRequest {
            return Err(EngineError::NotAllowed(
                "that contact has no pending request",
            ));
        }
        self.execute_proto(
            format!("set-pairwise-relationship:{}:contact", contact.identity),
            proto::client_command::Body::SetPairwiseRelationship(proto::SetPairwiseRelationship {
                identity: contact.identity_bytes().to_vec(),
                relationship: proto::PairwiseRelationship::Contact as i32,
            }),
        )?;
        if let Some(stored) = self.contact_mut(&contact.identity) {
            stored.relationship = Relationship::Contact;
        }
        self.save()?;
        let id = new_uuid();
        self.send_application(
            contact,
            proto::DirectApplication {
                application_id: id.clone(),
                body: Some(proto::direct_application::Body::ContactAcceptance(
                    proto::DirectContactAcceptance {},
                )),
            },
            Vec::new(),
        )?;
        self.record(
            &contact.identity,
            HistoryEntry {
                id,
                mine: true,
                text: "accepted the message request".into(),
                at_ms: now_ms(),
                delivery: None,
                system: true,
            },
        )
    }

    fn send_application(
        &mut self,
        contact: &Contact,
        application: proto::DirectApplication,
        sender_contact_card: Vec<u8>,
    ) -> Result<(), EngineError> {
        let command_id = format!("send-direct:{}", application.application_id);
        self.execute_proto(
            command_id,
            proto::client_command::Body::SendDirectApplication(proto::SendDirectApplication {
                recipient_identity: contact.identity_bytes().to_vec(),
                application: Some(application),
                local_only: false,
                sender_contact_card,
            }),
        )?;
        Ok(())
    }

    /// Everything the core still wants deposited on a relay. Re-derived from
    /// the durable snapshot each time, so a crash or a lost receipt simply
    /// means the item is deposited again (the recipient deduplicates).
    pub fn pending_deposits(&self) -> Result<Vec<Deposit>, EngineError> {
        let me = self.public_identity().to_vec();
        Ok(self
            .snapshot()?
            .pending_outbound
            .into_iter()
            .filter(|item| {
                item.kind == proto::OutboundKind::Pairwise as i32
                    && !item.local_only
                    && item.destination.len() == 32
                    && !item.payload.is_empty()
                    && card::is_valid_relay_url(&item.relay_url)
            })
            .map(|item| {
                let envelope = SessionEnvelope::new(
                    EnvelopeType::Pairwise,
                    me.clone(),
                    item.destination.clone(),
                    item.payload,
                );
                // One hop: an addressed relay delivery must not be re-flooded
                // onto the recipient's nearby links.
                let packet = MeshPacket::new(MeshPacket::random_id(), 1, envelope.encode());
                Deposit {
                    item_id: item.item_id,
                    relay_url: item.relay_url,
                    recipient: item.destination.try_into().unwrap(),
                    frame: base64_encode(&packet.encode()),
                }
            })
            .collect())
    }

    /// Records the relay's durable-storage receipt for an outbound item.
    pub fn deposit_confirmed(&mut self, item_id: &str) -> Result<(), EngineError> {
        self.execute_proto(
            format!("ack-outbound:{item_id}"),
            proto::client_command::Body::AcknowledgeEffects(proto::AcknowledgeEffects {
                outbound_item_ids: vec![item_id.to_owned()],
                event_ids: Vec::new(),
            }),
        )?;
        Ok(())
    }

    // MARK: - Receiving

    /// Applies one relay envelope (the base64-decoded `ciphertext` field).
    pub fn receive(&mut self, frame: &[u8]) -> (Disposition, Vec<Notice>) {
        let Ok(packet) = MeshPacket::decode(frame) else {
            return (Disposition::Consumed, Vec::new());
        };
        let Ok(envelope) = SessionEnvelope::decode(&packet.payload) else {
            return (Disposition::Consumed, Vec::new());
        };
        if envelope.kind != EnvelopeType::Pairwise || envelope.recipient != self.public_identity() {
            return (Disposition::Consumed, Vec::new());
        }
        // Keyed by the envelope, not the mesh packet id, so a re-deposit of
        // the same ciphertext under a fresh packet id is still one command.
        let request_id = format!("pairwise-{}", hex::encode(Sha256::digest(&packet.payload)));
        let applied = self.execute_proto(
            format!("pairwise-message:{request_id}"),
            proto::client_command::Body::ApplyInbound(proto::ApplyInbound {
                kind: proto::OutboundKind::Pairwise as i32,
                payload: envelope.payload,
                request_id,
                now_ms: now_ms(),
            }),
        );
        match applied {
            Ok(()) => match self.absorb_pending_events() {
                Ok(notices) => (Disposition::Consumed, notices),
                Err(_) => (Disposition::Retry, Vec::new()),
            },
            Err(EngineError::Core(error)) if is_permanent(&error) => {
                (Disposition::Consumed, Vec::new())
            }
            Err(_) => (Disposition::Retry, Vec::new()),
        }
    }

    /// Reduces the core's pending events into history, seals that history,
    /// and only then acknowledges the events.
    fn absorb_pending_events(&mut self) -> Result<Vec<Notice>, EngineError> {
        let events = self.snapshot()?.pending_events;
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let mut notices = Vec::new();
        let mut acknowledgements = Vec::new();
        let mut event_ids = Vec::new();
        for event in events {
            event_ids.push(event.event_id.clone());
            let Some(proto::app_event::Body::DirectApplicationReceived(received)) = event.body
            else {
                continue;
            };
            if let Some(ack) = self.absorb_direct(received, &mut notices)? {
                acknowledgements.push(ack);
            }
        }
        self.save()?;
        for (contact, message_id) in acknowledgements {
            self.send_application(
                &contact,
                proto::DirectApplication {
                    application_id: new_uuid(),
                    body: Some(proto::direct_application::Body::Acknowledgement(
                        proto::DirectAcknowledgement { message_id },
                    )),
                },
                Vec::new(),
            )?;
        }
        let digest = Sha256::digest(event_ids.join("\n").as_bytes());
        self.execute_proto(
            format!("ack-events:{}", hex::encode(digest)),
            proto::client_command::Body::AcknowledgeEffects(proto::AcknowledgeEffects {
                outbound_item_ids: Vec::new(),
                event_ids,
            }),
        )?;
        Ok(notices)
    }

    /// Returns the (contact, application id) to acknowledge, if any.
    fn absorb_direct(
        &mut self,
        received: proto::DirectApplicationReceived,
        notices: &mut Vec<Notice>,
    ) -> Result<Option<(Contact, String)>, EngineError> {
        let Ok(sender) = <[u8; 32]>::try_from(received.sender_identity.as_slice()) else {
            return Ok(None);
        };
        let contact = match self.find_by_identity(&sender).cloned() {
            Some(contact) => contact,
            None => {
                // Core already verified the card and admitted the request.
                let Ok(card) = card::verify(&received.sender_contact_card) else {
                    return Ok(None);
                };
                if card.identity != sender {
                    return Ok(None);
                }
                let contact = Contact {
                    identity: hex::encode(sender),
                    name: card.name,
                    relays: card.relay_urls,
                    relationship: Relationship::IncomingRequest,
                    verified: false,
                };
                self.app.contacts.push(contact.clone());
                contact
            }
        };
        let Some(application) = received.application else {
            return Ok(None);
        };
        let id = application.application_id.clone();
        use proto::direct_application::Body;
        match application.body {
            Some(Body::Message(message)) => {
                if self
                    .history(&contact.identity)
                    .iter()
                    .any(|entry| entry.id == id)
                {
                    return Ok(Some((contact, id)));
                }
                let text = card::sanitize_message(&message.text);
                self.push_history(
                    &contact.identity,
                    HistoryEntry {
                        id: id.clone(),
                        mine: false,
                        text: text.clone(),
                        at_ms: now_ms(),
                        delivery: None,
                        system: false,
                    },
                );
                notices.push(if contact.relationship == Relationship::IncomingRequest {
                    Notice::Request {
                        from: contact.name.clone(),
                        text,
                    }
                } else {
                    Notice::Message {
                        from: contact.name.clone(),
                        text,
                    }
                });
                Ok(Some((contact, id)))
            }
            Some(Body::Acknowledgement(ack)) => {
                if let Some(entry) = self
                    .app
                    .history
                    .get_mut(&contact.identity)
                    .and_then(|history| history.iter_mut().find(|entry| entry.id == ack.message_id))
                {
                    if entry.delivery != Some(Delivery::Delivered) {
                        entry.delivery = Some(Delivery::Delivered);
                        notices.push(Notice::Delivered {
                            to: contact.name.clone(),
                        });
                    }
                }
                Ok(None)
            }
            Some(Body::ContactAcceptance(_)) => {
                if let Some(stored) = self.contact_mut(&contact.identity) {
                    if stored.relationship == Relationship::OutgoingRequest {
                        stored.relationship = Relationship::Contact;
                        notices.push(Notice::Accepted {
                            by: contact.name.clone(),
                        });
                    }
                }
                self.push_system(&contact.identity, &id, "accepted your message request");
                Ok(Some((contact, id)))
            }
            Some(Body::Reaction(reaction)) => {
                let text = match reaction.emoji {
                    Some(emoji) => format!("reacted {}", card::sanitize_message(&emoji)),
                    None => "removed a reaction".into(),
                };
                notices.push(Notice::System {
                    from: contact.name.clone(),
                    text: text.clone(),
                });
                self.push_system(&contact.identity, &id, &text);
                Ok(Some((contact, id)))
            }
            Some(Body::ScreenshotNotice(_)) => {
                let text = "took a screenshot";
                notices.push(Notice::System {
                    from: contact.name.clone(),
                    text: text.into(),
                });
                self.push_system(&contact.identity, &id, text);
                Ok(Some((contact, id)))
            }
            Some(Body::RelayRecommendation(recommendation)) => {
                let urls: Vec<_> = recommendation
                    .relay_urls
                    .into_iter()
                    .filter(|url| card::is_valid_relay_url(url))
                    .collect();
                let text = format!("shared a relay: {}", urls.join(", "));
                notices.push(Notice::System {
                    from: contact.name.clone(),
                    text: text.clone(),
                });
                self.push_system(&contact.identity, &id, &text);
                Ok(Some((contact, id)))
            }
            // Ephemeral and transport-mode toggles are phone UI state; the
            // terminal acknowledges them so the sender's status settles.
            Some(Body::EphemeralState(_)) | Some(Body::TransportState(_)) => {
                Ok(Some((contact, id)))
            }
            None => Ok(None),
        }
    }

    // MARK: - Plumbing

    fn snapshot(&self) -> Result<proto::ClientSnapshot, EngineError> {
        let encoded = self.client.snapshot()?.encode();
        proto::ClientSnapshot::decode(encoded.as_slice())
            .map_err(|_| EngineError::Core(CoreError::Serialization))
    }

    fn execute(&mut self, command: ClientCommand) -> Result<(), EngineError> {
        self.client.execute(command)?;
        Ok(())
    }

    fn execute_proto(
        &mut self,
        command_id: String,
        body: proto::client_command::Body,
    ) -> Result<(), EngineError> {
        let command = proto::ClientCommand {
            version: COMMAND_VERSION,
            command_id,
            body: Some(body),
        };
        self.execute(ClientCommand::decode(&command.encode_to_vec())?)
    }

    fn find_by_identity(&self, identity: &[u8; 32]) -> Option<&Contact> {
        let key = hex::encode(identity);
        self.app
            .contacts
            .iter()
            .find(|contact| contact.identity == key)
    }

    fn contact_mut(&mut self, identity: &str) -> Option<&mut Contact> {
        self.app
            .contacts
            .iter_mut()
            .find(|contact| contact.identity == identity)
    }

    fn push_history(&mut self, identity: &str, entry: HistoryEntry) {
        let history = self.app.history.entry(identity.to_owned()).or_default();
        history.push(entry);
        if history.len() > MAX_HISTORY_PER_CONTACT {
            let excess = history.len() - MAX_HISTORY_PER_CONTACT;
            history.drain(..excess);
        }
    }

    fn push_system(&mut self, identity: &str, id: &str, text: &str) {
        if self.history(identity).iter().any(|entry| entry.id == id) {
            return;
        }
        self.push_history(
            identity,
            HistoryEntry {
                id: id.to_owned(),
                mine: false,
                text: text.to_owned(),
                at_ms: now_ms(),
                delivery: None,
                system: true,
            },
        );
    }

    fn record(&mut self, identity: &str, entry: HistoryEntry) -> Result<(), EngineError> {
        self.push_history(identity, entry);
        self.save()
    }

    fn save(&mut self) -> Result<(), EngineError> {
        let bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(&self.app).map_err(|_| VaultError::Corrupt("app state"))?,
        );
        self.vault.store(APP_LABEL, &bytes)?;
        Ok(())
    }
}

/// A failure about the message itself gives the same answer on every
/// redelivery, so the relay copy is consumed; anything about this device may
/// clear and keeps the copy. Mirrors the app's `TransportMessageDisposition`.
fn is_permanent(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::InvalidKey
            | CoreError::InvalidSignature
            | CoreError::MalformedBundle
            | CoreError::NotAPreKeyMessage
            | CoreError::SessionCreation(_)
            | CoreError::Decryption(_)
            | CoreError::ResourceLimit(_)
            | CoreError::UnsupportedVersion { .. }
    )
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

/// A random RFC 4122 v4 UUID, so application ids match the app's format.
pub fn new_uuid() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("OS entropy source failed");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode_upper(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::TEST_COST;

    fn engine(dir: &std::path::Path, name: &str, relay: &str) -> Engine {
        let vault = Vault::create(dir, "pw", TEST_COST).unwrap();
        Engine::create(vault, name, vec![relay.into()]).unwrap()
    }

    /// Carries every pending deposit from `from` to `to`, as a relay would.
    fn deliver(from: &mut Engine, to: &mut Engine) -> Vec<Notice> {
        use base64::Engine as _;
        let mut notices = Vec::new();
        for deposit in from.pending_deposits().unwrap() {
            assert_eq!(deposit.recipient, to.public_identity());
            let frame = base64::engine::general_purpose::STANDARD
                .decode(&deposit.frame)
                .unwrap();
            let (disposition, mut received) = to.receive(&frame);
            assert_eq!(disposition, Disposition::Consumed);
            notices.append(&mut received);
            from.deposit_confirmed(&deposit.item_id).unwrap();
        }
        notices
    }

    #[test]
    fn request_accept_message_and_delivery_receipts_round_trip() {
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut alice = engine(a_dir.path(), "Alice", "wss://a.relay.example/ws");
        let mut bob = engine(b_dir.path(), "Bob", "wss://b.relay.example/ws");

        let bob_card = card::share_link(&bob.card().unwrap());
        let bob_contact = alice.add_contact(&bob_card, false).unwrap();
        assert_eq!(
            bob_contact.relays,
            vec!["wss://b.relay.example/ws".to_string()]
        );
        alice.send_text(&bob_contact, "hi bob").unwrap();
        assert!(alice.send_text(&bob_contact, "again").is_err());
        assert!(alice
            .pending_deposits()
            .unwrap()
            .iter()
            .all(|deposit| deposit.relay_url == "wss://b.relay.example/ws"));

        let notices = deliver(&mut alice, &mut bob);
        assert_eq!(
            notices,
            vec![Notice::Request {
                from: "Alice".into(),
                text: "hi bob".into()
            }]
        );
        let alice_contact = bob.resolve("alice").unwrap();
        assert_eq!(alice_contact.relationship, Relationship::IncomingRequest);
        assert!(bob.send_text(&alice_contact, "nope").is_err());

        bob.accept(&alice_contact).unwrap();
        let notices = deliver(&mut bob, &mut alice);
        assert!(notices.contains(&Notice::Delivered { to: "Bob".into() }));
        assert!(notices.contains(&Notice::Accepted { by: "Bob".into() }));
        deliver(&mut alice, &mut bob);

        let alice_contact = bob.resolve("alice").unwrap();
        bob.send_text(&alice_contact, "welcome").unwrap();
        let notices = deliver(&mut bob, &mut alice);
        assert!(notices.contains(&Notice::Message {
            from: "Bob".into(),
            text: "welcome".into()
        }));
        assert_eq!(
            alice.safety_number(&alice.resolve("bob").unwrap()),
            bob.safety_number(&alice_contact)
        );
    }

    #[test]
    fn redelivered_and_garbage_frames_are_consumed_without_duplicates() {
        use base64::Engine as _;
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut alice = engine(a_dir.path(), "Alice", "wss://a.relay.example/ws");
        let mut bob = engine(b_dir.path(), "Bob", "wss://b.relay.example/ws");
        let bob_contact = alice
            .add_contact(&card::qr_payload(&bob.card().unwrap()), true)
            .unwrap();
        bob.add_contact(&card::qr_payload(&alice.card().unwrap()), true)
            .unwrap();
        alice.send_text(&bob_contact, "once").unwrap();
        let deposit = alice.pending_deposits().unwrap().remove(0);
        let frame = base64::engine::general_purpose::STANDARD
            .decode(&deposit.frame)
            .unwrap();
        assert_eq!(bob.receive(&frame).0, Disposition::Consumed);
        assert_eq!(bob.receive(&frame).0, Disposition::Consumed);
        assert_eq!(bob.history(&hex::encode(alice.public_identity())).len(), 1);
        assert_eq!(bob.receive(b"garbage").0, Disposition::Consumed);
    }

    #[test]
    fn state_survives_reopen_and_wrong_passphrase_is_refused() {
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut alice = engine(a_dir.path(), "Alice", "wss://a.relay.example/ws");
        let bob = engine(b_dir.path(), "Bob", "wss://b.relay.example/ws");
        let bob_contact = alice
            .add_contact(&card::share_link(&bob.card().unwrap()), true)
            .unwrap();
        alice.send_text(&bob_contact, "persisted").unwrap();
        let identity = alice.public_identity();
        drop(alice);

        assert!(Engine::open(Vault::open(a_dir.path(), "wrong").unwrap()).is_err());
        let alice = Engine::open(Vault::open(a_dir.path(), "pw").unwrap()).unwrap();
        assert_eq!(alice.public_identity(), identity);
        assert_eq!(alice.history(&bob_contact.identity)[0].text, "persisted");
        assert_eq!(alice.pending_deposits().unwrap().len(), 1);
    }
}
