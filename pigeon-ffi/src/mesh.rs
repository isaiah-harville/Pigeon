//! UniFFI surface for `pigeon-mesh` — the transport-agnostic mesh layer.
//!
//! Like the crypto surface in [`crate`], this is deliberately thin and
//! **byte-oriented**: the value types cross as plain records, the stateful
//! routers/(de)fragmenters cross as objects, and every payload is opaque bytes.
//! `pigeon-mesh` itself stays free of any UniFFI coupling; all the wire framing
//! and routing logic lives there, shared with non-Apple clients.

use std::sync::{Arc, Mutex};

use pigeon_mesh::{envelope as core_env, fragment as core_frag, packet as core_pkt};

/// Everything the mesh FFI can fail with, unifying the three `pigeon-mesh`
/// error enums. Decoding errors are surfaced (never papered over) so the host
/// drops malformed frames rather than acting on them.
#[derive(Debug, uniffi::Error)]
pub enum MeshError {
    /// A packet, fragment, or envelope byte encoding was malformed.
    Malformed,
    /// A fragment's index/count fields were inconsistent.
    Inconsistent,
    /// A reassembled message exceeded the configured size limit.
    TooLarge,
    /// A message needed more fragments than the wire format can address.
    TooManyFragments,
}

impl std::fmt::Display for MeshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MeshError::Malformed => "malformed mesh framing",
            MeshError::Inconsistent => "inconsistent fragment",
            MeshError::TooLarge => "reassembled message too large",
            MeshError::TooManyFragments => "message needs too many fragments",
        };
        f.write_str(s)
    }
}

impl std::error::Error for MeshError {}

impl From<core_pkt::MeshError> for MeshError {
    fn from(_: core_pkt::MeshError) -> Self {
        MeshError::Malformed
    }
}

impl From<core_env::EnvelopeError> for MeshError {
    fn from(_: core_env::EnvelopeError) -> Self {
        MeshError::Malformed
    }
}

impl From<core_frag::FragmentationError> for MeshError {
    fn from(e: core_frag::FragmentationError) -> Self {
        match e {
            core_frag::FragmentationError::MalformedFragment => MeshError::Malformed,
            core_frag::FragmentationError::InconsistentFragment => MeshError::Inconsistent,
            core_frag::FragmentationError::MessageTooLarge => MeshError::TooLarge,
            core_frag::FragmentationError::TooManyFragments => MeshError::TooManyFragments,
        }
    }
}

// ---------------------------------------------------------------------------
// Value types (records) + conversions to/from the pigeon-mesh core structs.
// ---------------------------------------------------------------------------

/// An end-to-end mesh packet (`version ‖ ttl ‖ packetID(16) ‖ payload`).
#[derive(uniffi::Record, Clone)]
pub struct MeshPacket {
    pub packet_id: Vec<u8>,
    pub ttl: u8,
    pub payload: Vec<u8>,
}

impl From<core_pkt::MeshPacket> for MeshPacket {
    fn from(p: core_pkt::MeshPacket) -> Self {
        Self {
            packet_id: p.packet_id,
            ttl: p.ttl,
            payload: p.payload,
        }
    }
}

impl From<MeshPacket> for core_pkt::MeshPacket {
    fn from(p: MeshPacket) -> Self {
        core_pkt::MeshPacket::new(p.packet_id, p.ttl, p.payload)
    }
}

/// One BLE-sized piece of a logical message.
#[derive(uniffi::Record, Clone)]
pub struct Fragment {
    pub message_id: u16,
    pub index: u16,
    pub count: u16,
    pub payload: Vec<u8>,
}

impl From<core_frag::Fragment> for Fragment {
    fn from(f: core_frag::Fragment) -> Self {
        Self {
            message_id: f.message_id,
            index: f.index,
            count: f.count,
            payload: f.payload,
        }
    }
}

impl From<Fragment> for core_frag::Fragment {
    fn from(f: Fragment) -> Self {
        core_frag::Fragment::new(f.message_id, f.index, f.count, f.payload)
    }
}

/// What a [`SessionEnvelope`] carries.
#[derive(uniffi::Enum, Clone, Copy)]
pub enum EnvelopeType {
    Handshake,
    Message,
    RehandshakeRequest,
    Ack,
    Control,
    X3dhInit,
}

impl From<core_env::EnvelopeType> for EnvelopeType {
    fn from(t: core_env::EnvelopeType) -> Self {
        match t {
            core_env::EnvelopeType::Handshake => EnvelopeType::Handshake,
            core_env::EnvelopeType::Message => EnvelopeType::Message,
            core_env::EnvelopeType::RehandshakeRequest => EnvelopeType::RehandshakeRequest,
            core_env::EnvelopeType::Ack => EnvelopeType::Ack,
            core_env::EnvelopeType::Control => EnvelopeType::Control,
            core_env::EnvelopeType::X3dhInit => EnvelopeType::X3dhInit,
        }
    }
}

impl From<EnvelopeType> for core_env::EnvelopeType {
    fn from(t: EnvelopeType) -> Self {
        match t {
            EnvelopeType::Handshake => core_env::EnvelopeType::Handshake,
            EnvelopeType::Message => core_env::EnvelopeType::Message,
            EnvelopeType::RehandshakeRequest => core_env::EnvelopeType::RehandshakeRequest,
            EnvelopeType::Ack => core_env::EnvelopeType::Ack,
            EnvelopeType::Control => core_env::EnvelopeType::Control,
            EnvelopeType::X3dhInit => core_env::EnvelopeType::X3dhInit,
        }
    }
}

/// An identity-addressed envelope routed inside a packet payload.
#[derive(uniffi::Record, Clone)]
pub struct SessionEnvelope {
    pub kind: EnvelopeType,
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub payload: Vec<u8>,
}

impl From<core_env::SessionEnvelope> for SessionEnvelope {
    fn from(e: core_env::SessionEnvelope) -> Self {
        Self {
            kind: e.kind.into(),
            sender: e.sender,
            recipient: e.recipient,
            payload: e.payload,
        }
    }
}

impl From<SessionEnvelope> for core_env::SessionEnvelope {
    fn from(e: SessionEnvelope) -> Self {
        core_env::SessionEnvelope::new(e.kind.into(), e.sender, e.recipient, e.payload)
    }
}

/// The outcome of ingesting a packet: an optional payload to deliver locally and
/// an optional packet to rebroadcast.
#[derive(uniffi::Record, Clone)]
pub struct Reception {
    pub deliver: Option<Vec<u8>>,
    pub relay: Option<MeshPacket>,
}

// ---------------------------------------------------------------------------
// Free functions: the value-type codecs (records can't carry methods).
// ---------------------------------------------------------------------------

/// A fresh random 16-byte packet id.
#[uniffi::export]
pub fn mesh_packet_random_id() -> Vec<u8> {
    core_pkt::MeshPacket::random_id()
}

#[uniffi::export]
pub fn encode_mesh_packet(packet: MeshPacket) -> Vec<u8> {
    core_pkt::MeshPacket::from(packet).encode()
}

#[uniffi::export]
pub fn decode_mesh_packet(data: Vec<u8>) -> Result<MeshPacket, MeshError> {
    Ok(core_pkt::MeshPacket::decode(&data)?.into())
}

/// The packet to relay (one fewer hop), or `None` at the hop limit.
#[uniffi::export]
pub fn relay_mesh_packet(packet: MeshPacket) -> Option<MeshPacket> {
    core_pkt::MeshPacket::from(packet).relayed().map(Into::into)
}

#[uniffi::export]
pub fn encode_fragment(fragment: Fragment) -> Vec<u8> {
    core_frag::Fragment::from(fragment).encode()
}

#[uniffi::export]
pub fn decode_fragment(data: Vec<u8>) -> Result<Fragment, MeshError> {
    Ok(core_frag::Fragment::decode(&data)?.into())
}

#[uniffi::export]
pub fn encode_session_envelope(envelope: SessionEnvelope) -> Vec<u8> {
    core_env::SessionEnvelope::from(envelope).encode()
}

#[uniffi::export]
pub fn decode_session_envelope(data: Vec<u8>) -> Result<SessionEnvelope, MeshError> {
    Ok(core_env::SessionEnvelope::decode(&data)?.into())
}

// ---------------------------------------------------------------------------
// Stateful objects: flood router, fragmenter, reassembler.
// ---------------------------------------------------------------------------

/// Flood-based mesh routing with duplicate suppression. Wraps the core router
/// behind a `Mutex` so the object's mutating operations are `&self` methods.
#[derive(uniffi::Object)]
pub struct MeshRouter {
    inner: Mutex<core_pkt::MeshRouter>,
}

#[uniffi::export]
impl MeshRouter {
    /// A router with the default hop limit (8) and seen-cache size (1024).
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(core_pkt::MeshRouter::default()),
        })
    }

    /// A router with an explicit hop limit and seen-cache capacity.
    #[uniffi::constructor]
    pub fn with_config(default_ttl: u8, seen_capacity: u32) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(core_pkt::MeshRouter::new(
                default_ttl,
                seen_capacity as usize,
            )),
        })
    }

    /// Wraps `payload` in a fresh, self-suppressed packet for sending.
    pub fn originate(&self, payload: Vec<u8>) -> MeshPacket {
        self.inner
            .lock()
            .expect("mesh router poisoned")
            .originate(payload)
            .into()
    }

    /// Processes an inbound packet; duplicates yield neither delivery nor relay.
    pub fn ingest(&self, packet: MeshPacket) -> Reception {
        let r = self
            .inner
            .lock()
            .expect("mesh router poisoned")
            .ingest(packet.into());
        Reception {
            deliver: r.deliver,
            relay: r.relay.map(Into::into),
        }
    }
}

/// Splits outbound messages into BLE-sized fragments with rolling message ids.
#[derive(uniffi::Object)]
pub struct Fragmenter {
    inner: Mutex<core_frag::Fragmenter>,
}

#[uniffi::export]
impl Fragmenter {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(core_frag::Fragmenter::default()),
        })
    }

    /// Fragments `message` into pieces of at most `max_payload_per_fragment`
    /// bytes. A zero size is rejected (rather than panicking across the FFI).
    pub fn fragment(
        &self,
        message: Vec<u8>,
        max_payload_per_fragment: u32,
    ) -> Result<Vec<Fragment>, MeshError> {
        if max_payload_per_fragment == 0 {
            return Err(MeshError::Inconsistent);
        }
        let frags = self
            .inner
            .lock()
            .expect("fragmenter poisoned")
            .fragment(&message, max_payload_per_fragment as usize)?;
        Ok(frags.into_iter().map(Into::into).collect())
    }
}

/// Reassembles fragments into whole messages, tolerant of reorder/duplication
/// and bounded against memory exhaustion.
#[derive(uniffi::Object)]
pub struct Reassembler {
    inner: Mutex<core_frag::Reassembler>,
}

#[uniffi::export]
impl Reassembler {
    /// A reassembler with the default bounds (256 KiB / 64 concurrent messages).
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(core_frag::Reassembler::default()),
        })
    }

    /// A reassembler with explicit size/concurrency bounds.
    #[uniffi::constructor]
    pub fn with_limits(max_message_bytes: u32, max_concurrent_messages: u32) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(core_frag::Reassembler::new(
                max_message_bytes as usize,
                max_concurrent_messages as usize,
            )),
        })
    }

    /// Feeds one fragment in; returns the whole message once complete.
    pub fn ingest(&self, fragment: Fragment) -> Result<Option<Vec<u8>>, MeshError> {
        Ok(self
            .inner
            .lock()
            .expect("reassembler poisoned")
            .ingest(fragment.into())?)
    }

    /// Number of in-flight (incomplete) messages currently buffered.
    pub fn pending_count(&self) -> u32 {
        self.inner
            .lock()
            .expect("reassembler poisoned")
            .pending_count() as u32
    }
}
