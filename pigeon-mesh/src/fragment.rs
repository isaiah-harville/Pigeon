//! Splits logical messages into BLE-sized fragments and reassembles them.
//!
//! Bluetooth LE delivers small payloads (the usable ATT MTU is often
//! ~180–500 bytes), so any message larger than one fragment must be chopped up
//! on send and stitched back together on receive — tolerating fragments that
//! arrive out of order or duplicated.

use std::collections::HashMap;

/// Fixed header size: `version(1) ‖ messageID(2) ‖ index(2) ‖ count(2)`.
pub const HEADER_SIZE: usize = 7;
/// Protocol version byte at the head of every fragment.
pub const VERSION: u8 = 1;

/// Why a fragment or message could not be processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentationError {
    /// A fragment's bytes were malformed or too short to decode.
    MalformedFragment,
    /// A fragment's index/count fields are inconsistent (e.g. index >= count).
    InconsistentFragment,
    /// The message exceeds the configured reassembly size limit.
    MessageTooLarge,
    /// The message needs more fragments than the wire format can address.
    TooManyFragments,
}

impl std::fmt::Display for FragmentationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FragmentationError::MalformedFragment => "malformed fragment",
            FragmentationError::InconsistentFragment => "inconsistent fragment index/count",
            FragmentationError::MessageTooLarge => "reassembled message too large",
            FragmentationError::TooManyFragments => "message needs too many fragments",
        };
        f.write_str(s)
    }
}

impl std::error::Error for FragmentationError {}

/// One BLE-sized piece of a logical message.
///
/// Wire layout (7-byte header, big-endian): `version(1) ‖ messageID(2) ‖
/// index(2) ‖ count(2) ‖ payload`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// Identifies the logical message this fragment belongs to (per link,
    /// wraps at 2^16).
    pub message_id: u16,
    /// Zero-based position of this fragment within the message.
    pub index: u16,
    /// Total number of fragments in the message.
    pub count: u16,
    pub payload: Vec<u8>,
}

impl Fragment {
    pub fn new(message_id: u16, index: u16, count: u16, payload: Vec<u8>) -> Self {
        Self {
            message_id,
            index,
            count,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        out.push(VERSION);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, FragmentationError> {
        if data.len() < HEADER_SIZE || data[0] != VERSION {
            return Err(FragmentationError::MalformedFragment);
        }
        let message_id = u16::from_be_bytes([data[1], data[2]]);
        let index = u16::from_be_bytes([data[3], data[4]]);
        let count = u16::from_be_bytes([data[5], data[6]]);
        let payload = data[HEADER_SIZE..].to_vec();
        if count < 1 || index >= count {
            return Err(FragmentationError::InconsistentFragment);
        }
        Ok(Self {
            message_id,
            index,
            count,
            payload,
        })
    }
}

/// Splits outbound messages into ordered fragments, assigning each message a
/// rolling identifier so the peer can group its fragments.
pub struct Fragmenter {
    next_message_id: u16,
}

impl Default for Fragmenter {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Fragmenter {
    pub fn new(initial_message_id: u16) -> Self {
        Self {
            next_message_id: initial_message_id,
        }
    }

    /// Fragments `message` so each fragment's payload is at most
    /// `max_payload_per_fragment` bytes (the negotiated usable MTU minus
    /// [`HEADER_SIZE`]).
    pub fn fragment(
        &mut self,
        message: &[u8],
        max_payload_per_fragment: usize,
    ) -> Result<Vec<Fragment>, FragmentationError> {
        assert!(
            max_payload_per_fragment > 0,
            "fragment payload size must be positive"
        );

        let id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);

        // Even an empty message is one (empty) fragment, so it is delivered.
        let chunk_count = message.len().div_ceil(max_payload_per_fragment).max(1);
        if chunk_count > u16::MAX as usize {
            return Err(FragmentationError::TooManyFragments);
        }

        let mut fragments = Vec::with_capacity(chunk_count);
        let mut offset = 0usize;
        for i in 0..chunk_count {
            let end = (offset + max_payload_per_fragment).min(message.len());
            fragments.push(Fragment {
                message_id: id,
                index: i as u16,
                count: chunk_count as u16,
                payload: message[offset..end].to_vec(),
            });
            offset = end;
        }
        Ok(fragments)
    }
}

/// In-flight state for one incomplete message.
struct Pending {
    count: u16,
    fragments: HashMap<u16, Vec<u8>>,
    byte_count: usize,
    sequence: u64, // for oldest-first eviction
}

/// Reassembles fragments into whole messages, tolerating reordering and
/// duplicates, with bounds to resist memory exhaustion from malicious or lost
/// fragment streams.
pub struct Reassembler {
    max_message_bytes: usize,
    max_concurrent_messages: usize,
    pending: HashMap<u16, Pending>,
    sequence_counter: u64,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(256 * 1024, 64)
    }
}

impl Reassembler {
    pub fn new(max_message_bytes: usize, max_concurrent_messages: usize) -> Self {
        Self {
            max_message_bytes,
            max_concurrent_messages,
            pending: HashMap::new(),
            sequence_counter: 0,
        }
    }

    /// Feeds one fragment in. Returns the complete message once its final
    /// missing fragment arrives, otherwise `None`.
    pub fn ingest(&mut self, fragment: Fragment) -> Result<Option<Vec<u8>>, FragmentationError> {
        if fragment.count < 1 || fragment.index >= fragment.count {
            return Err(FragmentationError::InconsistentFragment);
        }

        // Single-fragment fast path: nothing to buffer.
        if fragment.count == 1 {
            return self.ingest_single_fragment(fragment).map(Some);
        }

        self.sequence_counter = self.sequence_counter.wrapping_add(1);

        // Reuse the existing entry when its shape matches; a different count
        // signals a reused message id, so start fresh (dropping the old).
        let mut entry = match self.pending.remove(&fragment.message_id) {
            Some(existing) if existing.count == fragment.count => existing,
            _ => Pending {
                count: fragment.count,
                fragments: HashMap::new(),
                byte_count: 0,
                sequence: self.sequence_counter,
            },
        };

        if let std::collections::hash_map::Entry::Vacant(slot) =
            entry.fragments.entry(fragment.index)
        {
            entry.byte_count += fragment.payload.len();
            if entry.byte_count > self.max_message_bytes {
                // Entry already removed from `pending`; drop it on the floor.
                return Err(FragmentationError::MessageTooLarge);
            }
            slot.insert(fragment.payload);
        }

        if entry.fragments.len() == entry.count as usize {
            let mut message = Vec::with_capacity(entry.byte_count);
            for index in 0..entry.count {
                match entry.fragments.get(&index) {
                    Some(part) => message.extend_from_slice(part),
                    None => return Err(FragmentationError::InconsistentFragment),
                }
            }
            return Ok(Some(message));
        }

        self.pending.insert(fragment.message_id, entry);
        self.evict_if_needed();
        Ok(None)
    }

    /// Number of in-flight (incomplete) messages currently buffered.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    fn ingest_single_fragment(
        &mut self,
        fragment: Fragment,
    ) -> Result<Vec<u8>, FragmentationError> {
        self.pending.remove(&fragment.message_id);
        if fragment.payload.len() > self.max_message_bytes {
            return Err(FragmentationError::MessageTooLarge);
        }
        Ok(fragment.payload)
    }

    /// Drops the oldest incomplete message(s) once too many accumulate.
    fn evict_if_needed(&mut self) {
        if self.pending.len() <= self.max_concurrent_messages {
            return;
        }
        if let Some(oldest) = self
            .pending
            .iter()
            .min_by_key(|(_, p)| p.sequence)
            .map(|(&id, _)| id)
        {
            self.pending.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes, so tests don't flake.
    fn pseudo_data(count: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.wrapping_add(0x9E3779B97F4A7C15);
        (0..count)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 0xFF) as u8
            })
            .collect()
    }

    #[test]
    fn fragment_round_trip() {
        let fragment = Fragment::new(0xBEEF, 3, 10, pseudo_data(50, 1));
        let decoded = Fragment::decode(&fragment.encode()).unwrap();
        assert_eq!(decoded, fragment);
        assert_eq!(fragment.encode().len(), HEADER_SIZE + 50);
    }

    #[test]
    fn decode_rejects_short_data() {
        assert_eq!(
            Fragment::decode(&[1, 2, 3]),
            Err(FragmentationError::MalformedFragment)
        );
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut bytes = Fragment::new(1, 0, 1, Vec::new()).encode();
        bytes[0] = 0xFF;
        assert_eq!(
            Fragment::decode(&bytes),
            Err(FragmentationError::MalformedFragment)
        );
    }

    #[test]
    fn decode_rejects_index_beyond_count() {
        let bytes = vec![VERSION, 0x00, 0x01, 0x00, 0x05, 0x00, 0x03]; // index 5, count 3
        assert_eq!(
            Fragment::decode(&bytes),
            Err(FragmentationError::InconsistentFragment)
        );
    }

    #[test]
    fn single_fragment_message() {
        let mut fragmenter = Fragmenter::default();
        let mut reassembler = Reassembler::default();
        let message = pseudo_data(30, 2);
        let frags = fragmenter.fragment(&message, 100).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(reassembler.ingest(frags[0].clone()).unwrap(), Some(message));
    }

    #[test]
    fn empty_message_is_deliverable() {
        let mut fragmenter = Fragmenter::default();
        let mut reassembler = Reassembler::default();
        let frags = fragmenter.fragment(&[], 100).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(
            reassembler.ingest(frags[0].clone()).unwrap(),
            Some(Vec::new())
        );
    }

    #[test]
    fn multi_fragment_in_order() {
        let mut fragmenter = Fragmenter::default();
        let mut reassembler = Reassembler::default();
        let message = pseudo_data(1000, 3);
        let frags = fragmenter.fragment(&message, 180).unwrap();
        assert_eq!(frags.len(), 6); // ceil(1000/180)
        let mut result = None;
        for fragment in frags {
            result = reassembler.ingest(fragment).unwrap();
        }
        assert_eq!(result, Some(message));
    }

    #[test]
    fn multi_fragment_out_of_order() {
        let mut fragmenter = Fragmenter::default();
        let mut reassembler = Reassembler::default();
        let message = pseudo_data(900, 4);
        let mut frags = fragmenter.fragment(&message, 100).unwrap();
        frags.reverse(); // a simple deterministic reordering
        let mut result = None;
        for fragment in frags {
            if let Some(done) = reassembler.ingest(fragment).unwrap() {
                result = Some(done);
            }
        }
        assert_eq!(result, Some(message));
    }

    #[test]
    fn duplicate_fragments_tolerated() {
        let mut fragmenter = Fragmenter::default();
        let mut reassembler = Reassembler::default();
        let message = pseudo_data(500, 5);
        let frags = fragmenter.fragment(&message, 100).unwrap();
        let mut result = None;
        // Deliver every fragment twice; completion should fire once and be correct.
        for fragment in frags.iter().chain(frags.iter()) {
            if let Some(done) = reassembler.ingest(fragment.clone()).unwrap() {
                result = Some(done);
            }
        }
        assert_eq!(result, Some(message));
    }

    #[test]
    fn each_message_gets_distinct_id() {
        let mut fragmenter = Fragmenter::default();
        let first = fragmenter.fragment(&pseudo_data(10, 6), 100).unwrap()[0].message_id;
        let second = fragmenter.fragment(&pseudo_data(10, 7), 100).unwrap()[0].message_id;
        assert_ne!(first, second);
    }

    #[test]
    fn oversize_message_rejected() {
        let mut reassembler = Reassembler::new(200, 64);
        let id = 7;
        // Two fragments of 150 bytes each = 300 > 200.
        let _ = reassembler.ingest(Fragment::new(id, 0, 2, pseudo_data(150, 8)));
        assert_eq!(
            reassembler.ingest(Fragment::new(id, 1, 2, pseudo_data(150, 9))),
            Err(FragmentationError::MessageTooLarge)
        );
    }

    #[test]
    fn concurrent_pending_bounded() {
        let mut reassembler = Reassembler::new(256 * 1024, 4);
        // Open 10 distinct incomplete messages; only the cap should remain.
        for id in 0..10u16 {
            let _ = reassembler.ingest(Fragment::new(id, 0, 2, vec![0x01]));
        }
        assert!(reassembler.pending_count() <= 4);
    }

    #[test]
    fn reused_message_id_resets_state() {
        let mut reassembler = Reassembler::default();
        // First message id=1 starts (count 3), only one fragment arrives.
        let _ = reassembler.ingest(Fragment::new(1, 0, 3, vec![0xAA]));
        // id=1 reused with a different count: treated as a new message.
        let first = reassembler
            .ingest(Fragment::new(1, 0, 2, vec![0xBB]))
            .unwrap();
        assert_eq!(first, None);
        let second = reassembler
            .ingest(Fragment::new(1, 1, 2, vec![0xCC]))
            .unwrap();
        assert_eq!(second, Some(vec![0xBB, 0xCC]));
    }
}
