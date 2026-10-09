use super::{PigeonGroupPolicy, PolicyEvent};

#[derive(Clone, Debug)]
pub struct PendingMutation {
    pub(crate) commit: Vec<u8>,
    pub(crate) policy: PigeonGroupPolicy,
    pub(crate) event: PolicyEvent,
    pub(crate) welcome: Option<Vec<u8>>,
}

impl PendingMutation {
    pub fn commit(&self) -> &[u8] {
        &self.commit
    }

    pub fn event(&self) -> &PolicyEvent {
        &self.event
    }

    pub fn next_policy(&self) -> &PigeonGroupPolicy {
        &self.policy
    }

    pub fn welcome(&self) -> Option<&[u8]> {
        self.welcome.as_deref()
    }
}
