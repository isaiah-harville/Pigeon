use std::collections::BTreeSet;

use super::{GroupId, GroupMessageId};
use crate::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupDeliveryState {
    Sending,
    Sent,
    DeliveredTo { delivered: usize, intended: usize },
    Delivered,
    Failed,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryLedger {
    group_id: GroupId,
    message_id: GroupMessageId,
    epoch: u64,
    original_sender: [u8; 32],
    intended: BTreeSet<[u8; 32]>,
    acknowledged: BTreeSet<[u8; 32]>,
    terminal: Option<GroupDeliveryState>,
    sent: bool,
}

impl DeliveryLedger {
    pub fn new(
        group_id: GroupId,
        message_id: GroupMessageId,
        epoch: u64,
        original_sender: [u8; 32],
        intended: Vec<[u8; 32]>,
    ) -> Result<Self, Error> {
        let intended: BTreeSet<_> = intended.into_iter().collect();
        if intended.is_empty() || intended.contains(&original_sender) {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            group_id,
            message_id,
            epoch,
            original_sender,
            intended,
            acknowledged: BTreeSet::new(),
            terminal: None,
            sent: false,
        })
    }

    pub fn state(&self) -> GroupDeliveryState {
        if let Some(state) = self.terminal {
            return state;
        }
        let delivered = self.acknowledged.len();
        if delivered == self.intended.len() {
            GroupDeliveryState::Delivered
        } else if delivered > 0 {
            GroupDeliveryState::DeliveredTo {
                delivered,
                intended: self.intended.len(),
            }
        } else if self.sent {
            GroupDeliveryState::Sent
        } else {
            GroupDeliveryState::Sending
        }
    }

    pub fn mark_sent(&mut self) {
        if self.terminal.is_none() {
            self.sent = true;
        }
    }

    pub fn mark_failed(&mut self) {
        self.terminal = Some(GroupDeliveryState::Failed);
    }

    pub fn mark_expired(&mut self) {
        self.terminal = Some(GroupDeliveryState::Expired);
    }

    pub fn acknowledge(
        &mut self,
        authenticated_sender: [u8; 32],
        claimed_original_sender: [u8; 32],
        claimed_message_id: GroupMessageId,
    ) -> Result<bool, Error> {
        if claimed_original_sender != self.original_sender
            || claimed_message_id != self.message_id
            || !self.intended.contains(&authenticated_sender)
            || self.terminal.is_some()
        {
            return Err(Error::InvalidSignature);
        }
        Ok(self.acknowledged.insert(authenticated_sender))
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}
