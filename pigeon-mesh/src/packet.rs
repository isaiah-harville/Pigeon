//! The mesh envelope that rides inside transport messages: a unique packet id
//! for duplicate-suppression and a TTL for store-and-forward relaying.
//!
//! This is the layer that fixes duplicate delivery: the same logical message
//! may reach a device over several BLE paths (and several relay hops), but it
//! carries one packet id, so a seen-cache delivers it exactly once.

use std::collections::{HashSet, VecDeque};

/// Protocol version byte at the head of every packet.
pub const VERSION: u8 = 1;
/// Length of a packet id, in bytes.
pub const ID_SIZE: usize = 16;
/// Fixed header size: `version(1) ‖ ttl(1) ‖ packetID(16)`.
pub const HEADER_SIZE: usize = 18;

/// A malformed packet could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshError {
    /// The bytes were too short or carried an unknown version.
    MalformedPacket,
}

impl std::fmt::Display for MeshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed mesh packet")
    }
}

impl std::error::Error for MeshError {}

/// An end-to-end mesh packet. The `payload` is opaque to the mesh (it is
/// ciphertext); the mesh only reads the header to deduplicate and relay.
///
/// Wire layout (18-byte header): `version(1) ‖ ttl(1) ‖ packetID(16) ‖ payload`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshPacket {
    /// Unique per originated packet; the basis for dedup and loop prevention.
    pub packet_id: Vec<u8>,
    /// Remaining hops. Decremented on each relay; not relayed at 0.
    pub ttl: u8,
    pub payload: Vec<u8>,
}

impl MeshPacket {
    pub fn new(packet_id: Vec<u8>, ttl: u8, payload: Vec<u8>) -> Self {
        Self {
            packet_id,
            ttl,
            payload,
        }
    }

    /// Generates a fresh random 16-byte packet id (uniqueness, not secrecy, is
    /// what matters here).
    pub fn random_id() -> Vec<u8> {
        let mut id = vec![0u8; ID_SIZE];
        getrandom::getrandom(&mut id).expect("OS entropy source failed");
        id
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        out.push(VERSION);
        out.push(self.ttl);
        out.extend_from_slice(&self.packet_id);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, MeshError> {
        if data.len() < HEADER_SIZE || data[0] != VERSION {
            return Err(MeshError::MalformedPacket);
        }
        Ok(Self {
            ttl: data[1],
            packet_id: data[2..18].to_vec(),
            payload: data[18..].to_vec(),
        })
    }

    /// Returns the packet to relay (one fewer hop), or `None` if it has reached
    /// its hop limit and must not be forwarded.
    pub fn relayed(&self) -> Option<MeshPacket> {
        if self.ttl > 1 {
            Some(MeshPacket {
                packet_id: self.packet_id.clone(),
                ttl: self.ttl - 1,
                payload: self.payload.clone(),
            })
        } else {
            None
        }
    }
}

/// Bounded FIFO set of recently seen packet ids, used to drop duplicates and
/// prevent relay loops. When full, the oldest ids are forgotten (a re-seen old
/// packet may then be delivered again — an acceptable trade for bounded memory).
pub struct SeenCache {
    capacity: usize,
    order: VecDeque<Vec<u8>>,
    members: HashSet<Vec<u8>>,
}

impl SeenCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            members: HashSet::new(),
        }
    }

    /// Records `id`. Returns `true` if it was newly seen, `false` if a duplicate.
    pub fn insert(&mut self, id: &[u8]) -> bool {
        if self.members.contains(id) {
            return false;
        }
        self.members.insert(id.to_vec());
        self.order.push_back(id.to_vec());
        if self.order.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.members.remove(&evicted);
            }
        }
        true
    }

    pub fn contains(&self, id: &[u8]) -> bool {
        self.members.contains(id)
    }
}

/// The outcome of ingesting a packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reception {
    /// Payload to hand to the local app, or `None` if this was a duplicate.
    pub deliver: Option<Vec<u8>>,
    /// Packet to rebroadcast to other peers, or `None` if not relayed.
    pub relay: Option<MeshPacket>,
}

/// Flood-based mesh routing: originate packets, and on reception decide whether
/// to deliver locally and/or relay onward, deduplicating by packet id.
pub struct MeshRouter {
    default_ttl: u8,
    seen: SeenCache,
}

impl Default for MeshRouter {
    fn default() -> Self {
        Self::new(8, 1024)
    }
}

impl MeshRouter {
    pub fn new(default_ttl: u8, seen_capacity: usize) -> Self {
        Self {
            default_ttl,
            seen: SeenCache::new(seen_capacity),
        }
    }

    pub fn default_ttl(&self) -> u8 {
        self.default_ttl
    }

    /// Wraps `payload` in a fresh packet for sending. The id is pre-marked as
    /// seen so our own packet echoing back through the mesh is ignored.
    pub fn originate(&mut self, payload: Vec<u8>) -> MeshPacket {
        let packet = MeshPacket::new(MeshPacket::random_id(), self.default_ttl, payload);
        self.seen.insert(&packet.packet_id);
        packet
    }

    /// Processes an inbound packet. Duplicates yield no delivery and no relay.
    pub fn ingest(&mut self, packet: MeshPacket) -> Reception {
        if !self.seen.insert(&packet.packet_id) {
            return Reception {
                deliver: None,
                relay: None,
            };
        }
        let relay = packet.relayed();
        Reception {
            deliver: Some(packet.payload),
            relay,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(ttl: u8, payload: &[u8]) -> MeshPacket {
        MeshPacket::new(MeshPacket::random_id(), ttl, payload.to_vec())
    }

    #[test]
    fn packet_round_trip() {
        let p = packet(5, b"carrier");
        let decoded = MeshPacket::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
        assert_eq!(p.encode().len(), HEADER_SIZE + 7);
    }

    #[test]
    fn random_ids_are_unique_and_sized() {
        let first = MeshPacket::random_id();
        let second = MeshPacket::random_id();
        assert_eq!(first.len(), ID_SIZE);
        assert_ne!(first, second);
    }

    #[test]
    fn decode_rejects_short_or_bad_version() {
        assert_eq!(
            MeshPacket::decode(&[1, 2, 3]),
            Err(MeshError::MalformedPacket)
        );
        let mut bytes = packet(8, b"hi").encode();
        bytes[0] = 0x09;
        assert_eq!(MeshPacket::decode(&bytes), Err(MeshError::MalformedPacket));
    }

    #[test]
    fn relay_decrements_ttl() {
        assert_eq!(packet(3, b"hi").relayed().unwrap().ttl, 2);
    }

    #[test]
    fn relay_stops_at_hop_limit() {
        assert!(packet(1, b"hi").relayed().is_none());
        assert!(packet(0, b"hi").relayed().is_none());
    }

    #[test]
    fn seen_cache_detects_duplicates() {
        let mut cache = SeenCache::new(1024);
        let id = MeshPacket::random_id();
        assert!(cache.insert(&id));
        assert!(!cache.insert(&id));
        assert!(cache.contains(&id));
    }

    #[test]
    fn seen_cache_evicts_oldest() {
        let mut cache = SeenCache::new(2);
        let (first, second, third) = (
            MeshPacket::random_id(),
            MeshPacket::random_id(),
            MeshPacket::random_id(),
        );
        cache.insert(&first);
        cache.insert(&second);
        cache.insert(&third); // evicts first
        assert!(!cache.contains(&first));
        assert!(cache.contains(&second));
        assert!(cache.contains(&third));
    }

    #[test]
    fn originate_produces_deliverable_unique_packets() {
        let mut router = MeshRouter::new(8, 1024);
        let p = router.originate(b"msg".to_vec());
        assert_eq!(p.ttl, 8);
        assert_eq!(p.payload, b"msg");
    }

    #[test]
    fn ingest_delivers_once_then_dedupes() {
        let mut router = MeshRouter::default();
        let p = packet(8, b"once");
        let first = router.ingest(p.clone());
        assert_eq!(first.deliver.as_deref(), Some(&b"once"[..]));
        assert_eq!(first.relay.unwrap().ttl, 7);
        let second = router.ingest(p);
        assert!(second.deliver.is_none());
        assert!(second.relay.is_none());
    }

    #[test]
    fn ingest_duplicate_across_paths_is_the_duplicate_fix() {
        let mut router = MeshRouter::default();
        let mut originator = MeshRouter::default();
        let p = originator.originate(b"hello from A".to_vec());
        let via_one = router.ingest(p.clone());
        let via_two = router.ingest(p); // same packetID, different transport source
        assert_eq!(via_one.deliver.as_deref(), Some(&b"hello from A"[..]));
        assert!(via_two.deliver.is_none()); // delivered exactly once
    }

    #[test]
    fn originator_ignores_its_own_echo() {
        let mut router = MeshRouter::default();
        let p = router.originate(b"echo".to_vec());
        assert!(router.ingest(p).deliver.is_none());
    }

    #[test]
    fn ingest_at_ttl1_delivers_but_does_not_relay() {
        let mut router = MeshRouter::default();
        let result = router.ingest(packet(1, b"last hop"));
        assert_eq!(result.deliver.as_deref(), Some(&b"last hop"[..]));
        assert!(result.relay.is_none());
    }
}
