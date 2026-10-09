use prost::Message;

use crate::Error;
use crate::group::GroupId;
use crate::wire::{self, PROTOCOL_VERSION, proto};

include!("command_parts/pairwise_commands.rs");
include!("command_parts/group_commands.rs");
