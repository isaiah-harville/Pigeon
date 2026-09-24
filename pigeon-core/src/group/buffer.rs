use std::collections::{BTreeMap, HashSet};

use super::{GroupCiphertext, GroupId, GroupMessageId};
use crate::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferDisposition {
    Ready,
    Buffered { missing_from: u64, missing_to: u64 },
    Duplicate,
    DroppedStale,
    DroppedFutureGap,
    DroppedCapacity,
}

#[derive(Debug)]
pub struct EpochBuffer {
    maximum_messages: usize,
    maximum_bytes: usize,
    maximum_future_epochs: u64,
    bytes: usize,
    seen: HashSet<(GroupId, GroupMessageId)>,
    pending: BTreeMap<u64, Vec<GroupCiphertext>>,
}

impl EpochBuffer {
    pub fn new(maximum_messages: usize, maximum_bytes: usize, maximum_future_epochs: u64) -> Self {
        Self {
            maximum_messages,
            maximum_bytes,
            maximum_future_epochs,
            bytes: 0,
            seen: HashSet::new(),
            pending: BTreeMap::new(),
        }
    }

    pub fn push(
        &mut self,
        current_epoch: u64,
        ciphertext: GroupCiphertext,
    ) -> Result<BufferDisposition, Error> {
        let key = (ciphertext.group_id(), ciphertext.message_id());
        if self.seen.contains(&key) {
            return Ok(BufferDisposition::Duplicate);
        }
        if ciphertext.epoch() < current_epoch {
            return Ok(BufferDisposition::DroppedStale);
        }
        if ciphertext.epoch() == current_epoch {
            self.seen.insert(key);
            return Ok(BufferDisposition::Ready);
        }
        let gap = ciphertext
            .epoch()
            .checked_sub(current_epoch)
            .ok_or(Error::Serialization)?;
        if gap > self.maximum_future_epochs {
            return Ok(BufferDisposition::DroppedFutureGap);
        }
        let encoded_bytes = ciphertext.encode().len();
        let message_count: usize = self.pending.values().map(Vec::len).sum();
        if message_count >= self.maximum_messages
            || self.bytes.saturating_add(encoded_bytes) > self.maximum_bytes
        {
            return Ok(BufferDisposition::DroppedCapacity);
        }
        let epoch = ciphertext.epoch();
        self.pending.entry(epoch).or_default().push(ciphertext);
        self.seen.insert(key);
        self.bytes += encoded_bytes;
        Ok(BufferDisposition::Buffered {
            missing_from: current_epoch + 1,
            missing_to: epoch,
        })
    }

    pub fn drain_epoch(&mut self, epoch: u64) -> Vec<GroupCiphertext> {
        let messages = self.pending.remove(&epoch).unwrap_or_default();
        self.bytes = self.bytes.saturating_sub(
            messages
                .iter()
                .map(|ciphertext| ciphertext.encode().len())
                .sum::<usize>(),
        );
        messages
    }

    pub fn buffered_bytes(&self) -> usize {
        self.bytes
    }
}
