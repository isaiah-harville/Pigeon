// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Durable state for group mailboxes and the MLS commit coordinator.
//!
//! The in-memory stores remain the query path. Every successful mutation is
//! written through to SQLite while the owning store's lock is still held, so no
//! client can observe state that is not on disk. A failed write stops the
//! process instead of continuing: otherwise a restart could forget an append the
//! relay already acknowledged or, worse, re-sign a different candidate at a
//! coordinator sequence that clients already hold.
//!
//! The database holds exactly what the relay already holds in memory: opaque
//! ciphertext and MLS candidates, public capability keys, cursors, generations,
//! and timestamps. Expiry and cursor garbage collection are applied lazily on
//! disk, so the database may briefly hold rows memory has dropped; loading
//! re-applies both rules. Pairwise mailboxes stay memory-only because senders
//! retransmit until the recipient acknowledges.
//!
//! SQLite stores signed 64-bit integers. Several persisted values are chosen by
//! clients (for example authorization generations), so `u64` values are stored
//! as bit-preserving `i64` casts rather than range-checked conversions: a large
//! client value must round-trip, never fail a write and stop the relay.

use std::fmt;
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

pub const GROUP_DATABASE: &str = "groups.sqlite3";
pub const COORDINATOR_DATABASE: &str = "coordinator.sqlite3";

const GROUP_SCHEMA_VERSION: i64 = 5;
const COORDINATOR_SCHEMA_VERSION: i64 = 1;
const COORDINATOR_KEY: &str = "coordinator_public_key";

const GROUP_SCHEMA: &str = "
    CREATE TABLE groups (
        coordination_id BLOB PRIMARY KEY NOT NULL,
        permanent_controller_public_key BLOB NOT NULL,
        authorization_generation INTEGER NOT NULL,
        next_sequence INTEGER NOT NULL,
        revoked_at INTEGER,
        registered_at INTEGER NOT NULL,
        coordinator_active INTEGER NOT NULL,
        last_activity_at INTEGER NOT NULL,
        inactive INTEGER NOT NULL DEFAULT 0
    ) WITHOUT ROWID;
    CREATE TABLE capabilities (
        coordination_id BLOB NOT NULL
            REFERENCES groups(coordination_id) ON DELETE CASCADE,
        capability_id BLOB NOT NULL,
        public_key BLOB NOT NULL,
        can_append INTEGER NOT NULL,
        can_read INTEGER NOT NULL,
        can_control INTEGER NOT NULL,
        cursor INTEGER NOT NULL,
        PRIMARY KEY (coordination_id, capability_id)
    ) WITHOUT ROWID;
    CREATE TABLE entries (
        coordination_id BLOB NOT NULL
            REFERENCES groups(coordination_id) ON DELETE CASCADE,
        sequence INTEGER NOT NULL,
        ciphertext BLOB NOT NULL,
        timestamp INTEGER NOT NULL,
        PRIMARY KEY (coordination_id, sequence)
    );
    CREATE INDEX entries_by_timestamp ON entries(timestamp);
    CREATE TABLE retired_groups (
        coordination_id BLOB PRIMARY KEY NOT NULL,
        permanent_controller_public_key BLOB NOT NULL,
        terminal INTEGER NOT NULL
    ) WITHOUT ROWID;
";

const COORDINATOR_SCHEMA: &str = "
    CREATE TABLE metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value BLOB NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE logs (
        coordination_id BLOB PRIMARY KEY NOT NULL,
        next_sequence INTEGER NOT NULL,
        receipt_head BLOB NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE candidates (
        coordination_id BLOB NOT NULL
            REFERENCES logs(coordination_id) ON DELETE CASCADE,
        sequence INTEGER NOT NULL,
        prior_receipt_hash BLOB NOT NULL,
        claimed_base_epoch INTEGER NOT NULL,
        entry_hash BLOB NOT NULL,
        signature BLOB NOT NULL,
        candidate BLOB NOT NULL,
        timestamp INTEGER NOT NULL,
        submitter_capability_id BLOB NOT NULL,
        PRIMARY KEY (coordination_id, sequence)
    );
    CREATE INDEX candidates_by_timestamp ON candidates(timestamp);
";

include!("durable_parts/schema.rs");
include!("durable_parts/group_journal.rs");
include!("durable_parts/coordinator_journal.rs");
