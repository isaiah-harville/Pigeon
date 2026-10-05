// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use crate::coordinator::store::Config as CoordinatorConfig;
use crate::group::store::Config as GroupConfig;
use crate::invite::Config as InviteConfig;
use crate::mailbox::store::Config as MailboxConfig;

const DEFAULT_TTL_SECS: u64 = 30 * 24 * 3600;
// One MiB of opaque bytes expands below the client's two MiB JSON frame limit.
const MAX_FETCHED_ITEM_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct RelayConfig {
    pub bind_addr: String,
    pub max_connections: usize,
    pub mailbox: MailboxConfig,
    pub group: GroupConfig,
    pub group_admission_difficulty: u8,
    pub invite: InviteConfig,
    pub coordinator: CoordinatorConfig,
    pub apns_min_interval: Duration,
    pub coordinator_signing_seed: Option<[u8; 32]>,
    pub state_dir: PathBuf,
}

impl fmt::Debug for RelayConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayConfig")
            .field("bind_addr", &self.bind_addr)
            .field("max_connections", &self.max_connections)
            .field("mailbox", &self.mailbox)
            .field("group", &self.group)
            .field("invite", &self.invite)
            .field("coordinator", &self.coordinator)
            .field("apns_min_interval", &self.apns_min_interval)
            .field("state_dir", &self.state_dir)
            .field(
                "coordinator_signing_seed",
                &self.coordinator_signing_seed.map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    variable: &'static str,
    reason: &'static str,
}

impl ConfigError {
    #[cfg(test)]
    pub fn variable(&self) -> &'static str {
        self.variable
    }

    fn new(variable: &'static str, reason: &'static str) -> Self {
        Self { variable, reason }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid relay configuration in {}: {}",
            self.variable, self.reason
        )
    }
}

impl std::error::Error for ConfigError {}

fn validate_fetched_item_limit(variable: &'static str, value: usize) -> Result<(), ConfigError> {
    if value > MAX_FETCHED_ITEM_BYTES {
        return Err(ConfigError::new(variable, "must not exceed one MiB"));
    }
    Ok(())
}

impl RelayConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let bind_addr = lookup("PIGEON_RELAY_ADDR").unwrap_or_else(|| "0.0.0.0:8080".into());
        if bind_addr.trim().is_empty() {
            return Err(ConfigError::new("PIGEON_RELAY_ADDR", "must not be empty"));
        }
        let max_connections = parse_usize(&mut lookup, "PIGEON_RELAY_MAX_CONNECTIONS", 1024)?;

        let mailbox = MailboxConfig {
            ttl_secs: parse_u64(&mut lookup, "PIGEON_RELAY_TTL_SECS", DEFAULT_TTL_SECS)?,
            max_queue: parse_usize(&mut lookup, "PIGEON_RELAY_MAX_QUEUE", 1_000)?,
            max_mailboxes: parse_usize(&mut lookup, "PIGEON_RELAY_MAX_MAILBOXES", 10_000)?,
            max_total_bytes: parse_usize(
                &mut lookup,
                "PIGEON_RELAY_MAX_TOTAL_BYTES",
                512 * 1024 * 1024,
            )?,
        };
        let group = GroupConfig {
            ttl_secs: parse_u64(&mut lookup, "PIGEON_GROUP_TTL_SECS", DEFAULT_TTL_SECS)?,
            lease_secs: parse_u64(&mut lookup, "PIGEON_GROUP_LEASE_SECS", DEFAULT_TTL_SECS)?,
            max_groups: parse_usize(&mut lookup, "PIGEON_GROUP_MAX_GROUPS", 10_000)?,
            max_capabilities_per_group: parse_usize(
                &mut lookup,
                "PIGEON_GROUP_MAX_CAPABILITIES",
                128,
            )?,
            max_entry_bytes: parse_usize(&mut lookup, "PIGEON_GROUP_MAX_ENTRY_BYTES", 1024 * 1024)?,
            max_entries_per_group: parse_usize(&mut lookup, "PIGEON_GROUP_MAX_ENTRIES", 10_000)?,
            max_total_bytes: parse_usize(
                &mut lookup,
                "PIGEON_GROUP_MAX_TOTAL_BYTES",
                512 * 1024 * 1024,
            )?,
            max_fetch_batch_bytes: parse_usize(
                &mut lookup,
                "PIGEON_GROUP_MAX_FETCH_BYTES",
                4 * 1024 * 1024,
            )?,
        };
        let group_admission_difficulty =
            parse_u64(&mut lookup, "PIGEON_GROUP_ADMISSION_DIFFICULTY_BITS", 18)?;
        if group_admission_difficulty > 28 {
            return Err(ConfigError::new(
                "PIGEON_GROUP_ADMISSION_DIFFICULTY_BITS",
                "must be at most 28",
            ));
        }
        let group_admission_difficulty = group_admission_difficulty as u8;
        let invite = InviteConfig {
            ttl_secs: parse_u64(&mut lookup, "PIGEON_INVITE_TTL_SECS", 7 * 24 * 3600)?,
            max_mailboxes: parse_usize(&mut lookup, "PIGEON_INVITE_MAX_MAILBOXES", 10_000)?,
            max_entries_per_mailbox: parse_usize(&mut lookup, "PIGEON_INVITE_MAX_ENTRIES", 128)?,
            max_entry_bytes: parse_usize(&mut lookup, "PIGEON_INVITE_MAX_ENTRY_BYTES", 16 * 1024)?,
            max_total_bytes: parse_usize(
                &mut lookup,
                "PIGEON_INVITE_MAX_TOTAL_BYTES",
                64 * 1024 * 1024,
            )?,
            max_deposits_per_minute: parse_usize(
                &mut lookup,
                "PIGEON_INVITE_MAX_DEPOSITS_PER_MINUTE",
                120,
            )?,
        };
        if invite.ttl_secs > 365 * 24 * 3600 {
            return Err(ConfigError::new(
                "PIGEON_INVITE_TTL_SECS",
                "must be at most one year",
            ));
        }
        if invite.max_entry_bytes > 256 * 1024 {
            return Err(ConfigError::new(
                "PIGEON_INVITE_MAX_ENTRY_BYTES",
                "must be at most 256 KiB",
            ));
        }
        validate_not_larger(
            "PIGEON_INVITE_MAX_ENTRY_BYTES",
            invite.max_entry_bytes,
            invite.max_total_bytes,
        )?;
        if invite.max_entries_per_mailbox > 128 {
            return Err(ConfigError::new(
                "PIGEON_INVITE_MAX_ENTRIES",
                "must be at most 128",
            ));
        }
        validate_fetched_item_limit("PIGEON_GROUP_MAX_ENTRY_BYTES", group.max_entry_bytes)?;
        validate_not_larger(
            "PIGEON_GROUP_MAX_ENTRY_BYTES",
            group.max_entry_bytes,
            group.max_total_bytes,
        )?;
        validate_not_larger(
            "PIGEON_GROUP_MAX_FETCH_BYTES",
            group.max_fetch_batch_bytes,
            group.max_total_bytes,
        )?;

        let coordinator = CoordinatorConfig {
            max_logs: parse_usize(&mut lookup, "PIGEON_COORDINATOR_MAX_LOGS", group.max_groups)?,
            max_candidates_per_log: parse_usize(
                &mut lookup,
                "PIGEON_COORDINATOR_MAX_CANDIDATES_PER_LOG",
                10_000,
            )?,
            max_candidates_per_epoch: parse_usize(
                &mut lookup,
                "PIGEON_COORDINATOR_MAX_PER_EPOCH",
                256,
            )?,
            max_candidates_per_capability_per_epoch: parse_usize(
                &mut lookup,
                "PIGEON_COORDINATOR_MAX_PER_CAPABILITY_PER_EPOCH",
                8,
            )?,
            max_candidate_bytes: parse_usize(
                &mut lookup,
                "PIGEON_COORDINATOR_MAX_CANDIDATE_BYTES",
                1024 * 1024,
            )?,
            max_total_bytes: parse_usize(
                &mut lookup,
                "PIGEON_COORDINATOR_MAX_TOTAL_BYTES",
                256 * 1024 * 1024,
            )?,
            max_fetch_batch_bytes: parse_usize(
                &mut lookup,
                "PIGEON_COORDINATOR_MAX_FETCH_BYTES",
                4 * 1024 * 1024,
            )?,
            ttl_secs: parse_u64(&mut lookup, "PIGEON_COORDINATOR_TTL_SECS", DEFAULT_TTL_SECS)?,
        };
        validate_fetched_item_limit(
            "PIGEON_COORDINATOR_MAX_CANDIDATE_BYTES",
            coordinator.max_candidate_bytes,
        )?;
        validate_not_larger(
            "PIGEON_COORDINATOR_MAX_CANDIDATE_BYTES",
            coordinator.max_candidate_bytes,
            coordinator.max_total_bytes,
        )?;
        validate_not_larger(
            "PIGEON_COORDINATOR_MAX_FETCH_BYTES",
            coordinator.max_fetch_batch_bytes,
            coordinator.max_total_bytes,
        )?;
        validate_not_larger(
            "PIGEON_COORDINATOR_MAX_PER_CAPABILITY_PER_EPOCH",
            coordinator.max_candidates_per_capability_per_epoch,
            coordinator.max_candidates_per_epoch,
        )?;

        let apns_min_interval =
            Duration::from_secs(parse_u64(&mut lookup, "PIGEON_APNS_MIN_INTERVAL_SECS", 30)?);
        let coordinator_signing_seed = parse_seed(
            lookup("PIGEON_COORDINATOR_SIGNING_SEED_HEX"),
            "PIGEON_COORDINATOR_SIGNING_SEED_HEX",
        )?;
        let state_dir = PathBuf::from(
            lookup("PIGEON_RELAY_STATE_DIR").unwrap_or_else(|| "/var/lib/pigeon-relay".into()),
        );
        if state_dir.as_os_str().is_empty() {
            return Err(ConfigError::new(
                "PIGEON_RELAY_STATE_DIR",
                "must not be empty",
            ));
        }

        Ok(Self {
            bind_addr,
            max_connections,
            mailbox,
            group,
            group_admission_difficulty,
            invite,
            coordinator,
            apns_min_interval,
            coordinator_signing_seed,
            state_dir,
        })
    }
}

fn parse_u64(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    variable: &'static str,
    default: u64,
) -> Result<u64, ConfigError> {
    let Some(value) = lookup(variable) else {
        return Ok(default);
    };
    let parsed = value
        .parse::<u64>()
        .map_err(|_| ConfigError::new(variable, "must be a positive integer"))?;
    if parsed == 0 {
        return Err(ConfigError::new(variable, "must be greater than zero"));
    }
    Ok(parsed)
}

fn parse_usize(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    variable: &'static str,
    default: usize,
) -> Result<usize, ConfigError> {
    let parsed = parse_u64(lookup, variable, default as u64)?;
    usize::try_from(parsed).map_err(|_| ConfigError::new(variable, "does not fit this platform"))
}

fn parse_seed(
    value: Option<String>,
    variable: &'static str,
) -> Result<Option<[u8; 32]>, ConfigError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let decoded = hex::decode(value)
        .map_err(|_| ConfigError::new(variable, "must be 64 hexadecimal characters"))?;
    let seed = decoded
        .try_into()
        .map_err(|_| ConfigError::new(variable, "must encode exactly 32 bytes"))?;
    Ok(Some(seed))
}

fn validate_not_larger(
    variable: &'static str,
    value: usize,
    total: usize,
) -> Result<(), ConfigError> {
    if value > total {
        return Err(ConfigError::new(
            variable,
            "must not exceed its total-byte limit",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_values_use_documented_defaults() {
        let config = RelayConfig::from_lookup(|_| None).unwrap();
        assert_eq!(config.bind_addr, "0.0.0.0:8080");
        assert_eq!(config.mailbox.ttl_secs, 30 * 24 * 3600);
        assert_eq!(config.group.max_capabilities_per_group, 128);
        assert_eq!(config.group.lease_secs, 30 * 24 * 3600);
        assert_eq!(config.group_admission_difficulty, 18);
    }

    #[test]
    fn malformed_explicit_value_is_rejected() {
        let error = RelayConfig::from_lookup(|key| {
            (key == "PIGEON_RELAY_MAX_QUEUE").then(|| "many".to_string())
        })
        .unwrap_err();
        assert_eq!(error.variable(), "PIGEON_RELAY_MAX_QUEUE");
    }

    #[test]
    fn zero_capacity_is_rejected() {
        let error = RelayConfig::from_lookup(|key| {
            (key == "PIGEON_GROUP_MAX_GROUPS").then(|| "0".to_string())
        })
        .unwrap_err();
        assert_eq!(error.variable(), "PIGEON_GROUP_MAX_GROUPS");
    }

    #[test]
    fn invalid_group_admission_and_lease_settings_are_rejected() {
        for (variable, value) in [
            ("PIGEON_GROUP_ADMISSION_DIFFICULTY_BITS", "0"),
            ("PIGEON_GROUP_ADMISSION_DIFFICULTY_BITS", "29"),
            ("PIGEON_GROUP_LEASE_SECS", "0"),
        ] {
            let error =
                RelayConfig::from_lookup(|key| (key == variable).then(|| value.to_string()))
                    .unwrap_err();
            assert_eq!(error.variable(), variable);
        }
    }

    #[test]
    fn invite_and_socket_bounds_reject_undeliverable_or_unbounded_settings() {
        for (variable, value) in [
            ("PIGEON_RELAY_MAX_CONNECTIONS", "0"),
            ("PIGEON_INVITE_TTL_SECS", "31536001"),
            ("PIGEON_INVITE_MAX_ENTRY_BYTES", "262145"),
        ] {
            let error =
                RelayConfig::from_lookup(|key| (key == variable).then(|| value.to_string()))
                    .unwrap_err();
            assert_eq!(error.variable(), variable);
        }
    }

    #[test]
    fn fetched_item_limits_keep_single_json_frame_below_client_limit() {
        for variable in [
            "PIGEON_GROUP_MAX_ENTRY_BYTES",
            "PIGEON_COORDINATOR_MAX_CANDIDATE_BYTES",
        ] {
            let error = RelayConfig::from_lookup(|key| {
                (key == variable).then(|| (1024 * 1024 + 1).to_string())
            })
            .unwrap_err();
            assert_eq!(error.variable(), variable);
        }
    }

    #[test]
    fn coordinator_seed_is_redacted_from_debug_output() {
        let config = RelayConfig::from_lookup(|key| {
            (key == "PIGEON_COORDINATOR_SIGNING_SEED_HEX").then(|| "11".repeat(32))
        })
        .unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&"11".repeat(32)));
    }
}
