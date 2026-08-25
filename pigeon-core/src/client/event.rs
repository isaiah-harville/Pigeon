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
}

impl ClientOutput {
    pub(crate) fn empty(checkpoint_generation: u64) -> Self {
        Self {
            checkpoint_generation,
            events: Vec::new(),
            outbound: Vec::new(),
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
        }
        .encode_to_vec()
    }
}
