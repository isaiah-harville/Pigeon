// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Per-socket handling for the isolated opaque group-message service.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, FromRef, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::time::{timeout_at, Duration, Instant};

use super::protocol::{
    decode_capability, decode_group_capability, decode_public_key, gate_group_message,
    registration_transcript, verify_admission_solution, verify_challenge, verify_registration,
    GroupClientMsg, GroupEntryWire, GroupProtocolGate, GroupServerMsg, MAX_GROUP_FRAME_BYTES,
};
use super::store::GroupCapability;
use super::{RegistrationAttempts, Service, Subscriber};
use crate::app::{AppState, SUBSCRIBER_CHANNEL_CAPACITY};
use crate::clock::now;
use crate::coordinator::{self, protocol::CandidateWire};
use crate::push::{self, PushRegistry};
use crate::socket_admission::{client_ip, SocketAdmission};

include!("connection_parts/state.rs");
include!("connection_parts/socket.rs");
include!("connection_parts/delivery.rs");
