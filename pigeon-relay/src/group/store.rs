// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Isolated, bounded storage for opaque group application ciphertexts.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::durable::{
    fail_stop, CapabilityRecord, DurableError, GroupAuthorization, GroupJournal, GroupRecord,
};

pub const GROUP_ID_BYTES: usize = 32;
pub const CAPABILITY_KEY_BYTES: usize = 32;

include!("store_parts/types.rs");
include!("store_parts/registration.rs");
include!("store_parts/delivery.rs");
include!("store_parts/maintenance.rs");
