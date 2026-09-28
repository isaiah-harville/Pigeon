use prost::Message;

use crate::wire::proto;

#[derive(Clone, Debug)]
pub struct AppEvent {
    pub(crate) inner: proto::AppEvent,
}

impl AppEvent {
    pub fn encode(&self) -> Vec<u8> {
        self.inner.encode_to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct OutboundItem {
    pub(crate) inner: proto::OutboundItem,
}

impl OutboundItem {
    pub fn encode(&self) -> Vec<u8> {
        self.inner.encode_to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct ClientOutput {
    pub checkpoint_generation: u64,
    pub events: Vec<AppEvent>,
    pub outbound: Vec<OutboundItem>,
    pub group_message_outcome: GroupMessageOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupMessageOutcome {
    Unspecified,
    Accepted,
    Rejected,
}

#[derive(Clone, Debug)]
pub struct ClientSnapshot {
    pub(crate) inner: proto::ClientSnapshot,
}

impl ClientSnapshot {
    pub fn encode(&self) -> Vec<u8> {
        self.inner.encode_to_vec()
    }
}

impl ClientOutput {
    pub(crate) fn empty(checkpoint_generation: u64) -> Self {
        Self {
            checkpoint_generation,
            events: Vec::new(),
            outbound: Vec::new(),
            group_message_outcome: GroupMessageOutcome::Unspecified,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::ClientOutput {
            checkpoint_generation: self.checkpoint_generation,
            events: self
                .events
                .iter()
                .map(|event| event.inner.clone())
                .collect(),
            outbound: self
                .outbound
                .iter()
                .map(|item| item.inner.clone())
                .collect(),
            group_message_outcome: match self.group_message_outcome {
                GroupMessageOutcome::Unspecified => proto::GroupMessageOutcome::Unspecified,
                GroupMessageOutcome::Accepted => proto::GroupMessageOutcome::Accepted,
                GroupMessageOutcome::Rejected => proto::GroupMessageOutcome::Rejected,
            } as i32,
        }
        .encode_to_vec()
    }
}
