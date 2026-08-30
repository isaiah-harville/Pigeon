use crate::identity::GroupMemberKeys;

pub type Actor = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupAction {
    Add {
        actor: Actor,
        member_keys: Box<GroupMemberKeys>,
    },
    Remove {
        actor: Actor,
        subject: [u8; 32],
    },
    Leave {
        actor: Actor,
        committer: Actor,
    },
    Promote {
        actor: Actor,
        subject: [u8; 32],
    },
    Demote {
        actor: Actor,
        subject: [u8; 32],
    },
    Rename {
        actor: Actor,
        name: String,
    },
    SetMesh {
        actor: Actor,
        enabled: bool,
    },
    SetRelay {
        actor: Actor,
        relay_url: String,
    },
    Dissolve {
        actor: Actor,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyEventKind {
    MemberAdded,
    MemberRemoved,
    MemberLeft,
    AdminPromoted,
    AdminDemoted,
    NameChanged,
    MeshChanged,
    RelayChanged,
    Dissolved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEvent {
    pub kind: PolicyEventKind,
    pub actor: Actor,
    pub subject: Option<[u8; 32]>,
    pub revision: u64,
}
