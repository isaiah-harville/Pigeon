// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! End-to-end checks of the group route using masked client WebSocket frames.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use crate::app::{self, AppState};
use crate::config::RelayConfig;
use crate::group::protocol::{challenge_transcript, GROUP_PROTOCOL_VERSION};
use crate::group::store::{CapabilityRegistration, GroupRegistration};

const GROUP_ID: [u8; 32] = [42; 32];

fn config(directory: &tempfile::TempDir) -> RelayConfig {
    let mut config = RelayConfig::from_env().unwrap();
    config.bind_addr = "127.0.0.1:0".into();
    config.state_dir = directory.path().to_path_buf();
    config.coordinator_signing_seed = Some([8; 32]);
    config.group.max_groups = 4;
    config.group.max_entries_per_group = 1024;
    config.group.max_total_bytes = 1024 * 1024;
    config.group.max_fetch_batch_bytes = 1024 * 1024;
    config.coordinator.max_logs = 4;
    config.coordinator.max_candidates_per_log = 1024;
    config.coordinator.max_candidates_per_epoch = 1024;
    config.coordinator.max_candidates_per_capability_per_epoch = 1024;
    config.coordinator.max_total_bytes = 1024 * 1024;
    config
}

fn keys() -> [SigningKey; 3] {
    [
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    ]
}

fn capability(index: usize, key: &SigningKey) -> CapabilityRegistration {
    CapabilityRegistration {
        capability_id: [index as u8 + 1; 32],
        public_key: key.verifying_key().to_bytes(),
        can_append: index == 0,
        can_read: index != 0,
        can_control: index == 0,
    }
}

fn register(state: &AppState, keys: &[SigningKey; 3]) {
    let capabilities = keys
        .iter()
        .enumerate()
        .map(|(index, key)| capability(index, key))
        .collect();
    state
        .group
        .store
        .lock()
        .unwrap()
        .register(GroupRegistration {
            coordination_id: GROUP_ID,
            authorization_generation: 0,
            permanent_controller_public_key: keys[0].verifying_key().to_bytes(),
            capabilities,
        })
        .unwrap();
}

async fn start(state: AppState) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app::router(state)).await.unwrap();
    });
    (address, task)
}

struct Socket(TcpStream);

impl Socket {
    fn connect(address: SocketAddr) -> Self {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.write_all(b"GET /group/ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            response.push(byte[0]);
        }
        assert!(response.starts_with(b"HTTP/1.1 101"));
        let mut socket = Self(stream);
        socket.send(json!({"type":"hello","min_protocol_version":GROUP_PROTOCOL_VERSION,"max_protocol_version":GROUP_PROTOCOL_VERSION}));
        assert_eq!(socket.receive()["type"], "compatible");
        socket
    }

    fn send(&mut self, value: Value) {
        self.send_text(&value.to_string());
    }

    fn send_text(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let mut frame = vec![0x81];
        match bytes.len() {
            0..=125 => frame.push(0x80 | bytes.len() as u8),
            126..=65535 => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            }
            _ => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            }
        }
        let mask = [17, 29, 43, 59];
        frame.extend_from_slice(&mask);
        frame.extend(
            bytes
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        self.0.write_all(&frame).unwrap();
    }

    fn receive(&mut self) -> Value {
        let mut head = [0; 2];
        self.0.read_exact(&mut head).unwrap();
        assert_eq!(head[0] & 0x0f, 1, "expected a text frame");
        let size = match head[1] & 0x7f {
            126 => {
                let mut bytes = [0; 2];
                self.0.read_exact(&mut bytes).unwrap();
                u16::from_be_bytes(bytes) as usize
            }
            127 => {
                let mut bytes = [0; 8];
                self.0.read_exact(&mut bytes).unwrap();
                u64::from_be_bytes(bytes) as usize
            }
            size => size as usize,
        };
        let mut body = vec![0; size];
        self.0.read_exact(&mut body).unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn authenticate(&mut self, index: usize, key: &SigningKey) {
        let capability_id = [index as u8 + 1; 32];
        self.send(json!({"type":"authenticate","coordination_id":hex::encode(GROUP_ID),"capability_id":hex::encode(capability_id)}));
        let challenge = self.receive();
        assert_eq!(challenge["type"], "challenge");
        let nonce: [u8; 32] = B64
            .decode(challenge["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let capability = crate::group::store::GroupCapability {
            coordination_id: GROUP_ID,
            capability_id,
            public_key: key.verifying_key().to_bytes(),
        };
        self.send(json!({"type":"auth","signature":B64.encode(key.sign(&challenge_transcript(&capability, &nonce)).to_bytes())}));
        assert_eq!(self.receive()["type"], "ok");
    }

    fn expect_no_frame(&mut self) {
        self.0
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut byte = [0];
        let result = self.0.read(&mut byte);
        assert!(
            matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock || error.kind() == std::io::ErrorKind::TimedOut)
        );
        self.0
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn backlog_over_512_is_fetchable_across_live_socket_pages() {
    let directory = tempfile::tempdir().unwrap();
    let state = app::build_state(config(&directory)).unwrap();
    let keys = keys();
    register(&state, &keys);
    let group = state
        .group
        .store
        .lock()
        .unwrap()
        .resolve_capability(GROUP_ID, [1; 32])
        .unwrap();
    for sequence in 1..=513_u16 {
        state
            .group
            .store
            .lock()
            .unwrap()
            .append(&group, sequence.to_be_bytes().to_vec(), crate::clock::now())
            .unwrap();
    }
    let (address, server) = start(state).await;
    let mut reader = Socket::connect(address);
    reader.authenticate(1, &keys[1]);
    reader.send(json!({"type":"fetch","after_cursor":0}));
    let first = reader.receive();
    let entries = first["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 512);
    assert_eq!(entries[0]["sequence"], 1);
    assert_eq!(entries[511]["sequence"], 512);
    reader.send(json!({"type":"fetch","after_cursor":512}));
    let second = reader.receive();
    assert_eq!(second["entries"].as_array().unwrap().len(), 1);
    assert_eq!(second["entries"][0]["sequence"], 513);
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_client_frame_does_not_hide_following_valid_fetch() {
    let directory = tempfile::tempdir().unwrap();
    let state = app::build_state(config(&directory)).unwrap();
    let keys = keys();
    register(&state, &keys);
    let group = state
        .group
        .store
        .lock()
        .unwrap()
        .resolve_capability(GROUP_ID, [1; 32])
        .unwrap();
    state
        .group
        .store
        .lock()
        .unwrap()
        .append(&group, vec![7], crate::clock::now())
        .unwrap();
    let (address, server) = start(state).await;
    let mut reader = Socket::connect(address);
    reader.authenticate(1, &keys[1]);
    reader.send_text("{bad json");
    assert_eq!(reader.receive()["type"], "error");
    reader.send(json!({"type":"fetch","after_cursor":0}));
    let response = reader.receive();
    assert_eq!(response["entries"][0]["ciphertext"], B64.encode([7]));
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn opaque_malformed_core_entry_does_not_hide_following_entry() {
    let directory = tempfile::tempdir().unwrap();
    let state = app::build_state(config(&directory)).unwrap();
    let keys = keys();
    register(&state, &keys);
    let (address, server) = start(state).await;
    let mut writer = Socket::connect(address);
    writer.authenticate(0, &keys[0]);
    writer.send(json!({"type":"append","ciphertext":B64.encode([0xff])}));
    assert_eq!(writer.receive()["sequence"], 1);
    writer.send(json!({"type":"append","ciphertext":B64.encode([0x01, 0x02])}));
    assert_eq!(writer.receive()["sequence"], 2);

    let mut reader = Socket::connect(address);
    reader.authenticate(1, &keys[1]);
    reader.send(json!({"type":"fetch","after_cursor":0}));
    let entries = reader.receive()["entries"].as_array().unwrap().clone();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["sequence"], 1);
    assert_eq!(entries[0]["ciphertext"], B64.encode([0xff]));
    assert_eq!(entries[1]["sequence"], 2);
    assert_eq!(entries[1]["ciphertext"], B64.encode([0x01, 0x02]));
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn coordinator_receipt_is_fetchable_after_reconnect_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let relay_config = config(&directory);
    let state = app::build_state(relay_config.clone()).unwrap();
    let keys = keys();
    register(&state, &keys);
    let (address, server) = start(state).await;
    let mut writer = Socket::connect(address);
    writer.authenticate(0, &keys[0]);
    writer.send(
        json!({"type":"coordinator_submit","claimed_base_epoch":0,"candidate":B64.encode([9])}),
    );
    let receipt = writer.receive();
    assert_eq!(receipt["type"], "coordinator_receipt");
    assert_eq!(receipt["receipt"]["sequence"], 1);
    drop(writer);
    server.abort();

    let restored = app::build_state(relay_config).unwrap();
    let (address, server) = start(restored).await;
    let mut reader = Socket::connect(address);
    reader.authenticate(1, &keys[1]);
    reader.send(json!({"type":"coordinator_fetch","after_sequence":0}));
    let fetched = reader.receive();
    assert_eq!(fetched["type"], "coordinator_candidates");
    assert_eq!(fetched["candidates"][0]["receipt"], receipt["receipt"]);
    reader.send(json!({"type":"coordinator_fetch","after_sequence":1}));
    assert!(reader.receive()["candidates"]
        .as_array()
        .unwrap()
        .is_empty());
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_live_reader_is_not_woken_by_later_append() {
    let directory = tempfile::tempdir().unwrap();
    let state = app::build_state(config(&directory)).unwrap();
    let keys = keys();
    register(&state, &keys);
    let (address, server) = start(state).await;
    let mut writer = Socket::connect(address);
    writer.authenticate(0, &keys[0]);
    let mut removed = Socket::connect(address);
    removed.authenticate(1, &keys[1]);
    let mut retained = Socket::connect(address);
    retained.authenticate(2, &keys[2]);
    let mut controller = capability(0, &keys[0]);
    controller.can_read = true;
    let mut retained_capability = capability(2, &keys[2]);
    retained_capability.can_append = true;
    let newcomer = SigningKey::from_bytes(&[4; 32]);
    let added_capability = CapabilityRegistration {
        capability_id: [4; 32],
        public_key: newcomer.verifying_key().to_bytes(),
        can_append: true,
        can_read: true,
        can_control: false,
    };
    let encode = |capability: CapabilityRegistration| {
        json!({
            "capability_id":hex::encode(capability.capability_id),
            "public_key":hex::encode(capability.public_key),
            "can_append":capability.can_append,
            "can_read":capability.can_read,
            "can_control":capability.can_control
        })
    };
    writer.send(json!({"type":"replace_capabilities","expected_generation":0,"new_generation":1,"permanent_controller_public_key":hex::encode(keys[0].verifying_key().to_bytes()),"capabilities":[encode(controller),encode(retained_capability),encode(added_capability)]}));
    assert_eq!(writer.receive()["type"], "ok");
    writer.send(json!({"type":"append","ciphertext":B64.encode([5])}));
    assert_eq!(writer.receive()["type"], "appended");
    assert_eq!(retained.receive()["type"], "wake");
    removed.expect_no_frame();
    removed.send(json!({"type":"fetch","after_cursor":0}));
    assert_eq!(removed.receive()["type"], "error");
    server.abort();
}
