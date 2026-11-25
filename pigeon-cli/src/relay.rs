// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Relay transport for the terminal client, speaking the same mailbox
//! protocol as the iOS app (`pigeon-relay/src/mailbox/protocol.rs`).
//!
//! * **Receiving:** one authenticated subscription per relay we advertise.
//!   The relay challenges us to sign a nonce with the identity key that *is*
//!   the mailbox address. An envelope is acked only after the engine has
//!   durably applied it (or found it permanently unusable).
//! * **Sending:** one publish-only connection per recipient relay. Deposits
//!   carry the core outbound item id as `request_id`, so each `published`
//!   receipt retires exactly one item; anything unconfirmed is re-sent after a
//!   timeout or reconnect (the recipient's core deduplicates).
//!
//! Every socket runs a heartbeat and an idle deadline, so a half-open
//! connection is detected and replaced instead of silently swallowing traffic.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Notify};
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};
use tokio_tungstenite::tungstenite::Message;

use crate::engine::{Deposit, Disposition, Engine, Notice};

const MIN_PROTOCOL: u32 = 2;
const MAX_PROTOCOL: u32 = 3;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const PING_EVERY: Duration = Duration::from_secs(20);
const IDLE_LIMIT: Duration = Duration::from_secs(60);
const RESEND_AFTER: Duration = Duration::from_secs(30);
const OUTBOX_SWEEP: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// What the transport reports to the user interface.
#[derive(Debug, Clone)]
pub enum Event {
    Notice(Notice),
    Status(String),
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Clone)]
pub struct Hub {
    engine: Arc<Mutex<Engine>>,
    events: mpsc::UnboundedSender<Event>,
    outbox_changed: Arc<Notify>,
    in_flight: Arc<Mutex<HashMap<String, Instant>>>,
    publishers: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Deposit>>>>,
    online: Arc<Mutex<HashSet<String>>>,
}

impl Hub {
    pub fn new(engine: Arc<Mutex<Engine>>, events: mpsc::UnboundedSender<Event>) -> Self {
        Self {
            engine,
            events,
            outbox_changed: Arc::new(Notify::new()),
            in_flight: Arc::default(),
            publishers: Arc::default(),
            online: Arc::default(),
        }
    }

    /// Starts receiving on our own relays and draining the outbox.
    pub fn start(&self, receive: bool) {
        if receive {
            let relays = self.engine.lock().unwrap().relays().to_vec();
            for url in relays {
                let hub = self.clone();
                tokio::spawn(async move { hub.supervise_mailbox(url).await });
            }
        }
        let hub = self.clone();
        tokio::spawn(async move { hub.run_outbox().await });
    }

    /// Wakes the outbox after a local command produced new deposits.
    pub fn kick(&self) {
        self.outbox_changed.notify_one();
    }

    pub fn online_relays(&self) -> Vec<String> {
        let mut relays: Vec<_> = self.online.lock().unwrap().iter().cloned().collect();
        relays.sort();
        relays
    }

    pub fn pending_count(&self) -> usize {
        self.engine
            .lock()
            .unwrap()
            .pending_deposits()
            .map_or(0, |deposits| deposits.len())
    }

    fn status(&self, message: impl Into<String>) {
        let _ = self.events.send(Event::Status(message.into()));
    }

    // MARK: - Receiving

    async fn supervise_mailbox(self, url: String) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let started = Instant::now();
            match self.serve_mailbox(&url).await {
                Ok(()) => {}
                Err(error) => self.status(format!("{} offline: {error}", host(&url))),
            }
            self.online.lock().unwrap().remove(&url);
            // A connection that was healthy for a while reconnects promptly.
            if started.elapsed() > Duration::from_secs(60) {
                backoff = Duration::from_secs(1);
            }
            sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    async fn serve_mailbox(&self, url: &str) -> Result<(), String> {
        let mut socket = connect(url).await?;
        let identity = self.engine.lock().unwrap().public_identity();
        send(
            &mut socket,
            json!({"type": "subscribe", "mailbox": hex::encode(identity)}),
        )
        .await?;
        let challenge = expect(&mut socket, "challenge").await?;
        let nonce = challenge["nonce"]
            .as_str()
            .and_then(|value| B64.decode(value).ok())
            .ok_or("relay sent a malformed challenge")?;
        // The mailbox challenge is signed with the root identity key, the
        // same key that addresses the mailbox (as the app does).
        let signature = self.engine.lock().unwrap().sign_relay_challenge(&nonce);
        send(
            &mut socket,
            json!({"type": "auth", "signature": B64.encode(signature)}),
        )
        .await?;
        expect(&mut socket, "ok").await?;
        self.online.lock().unwrap().insert(url.to_owned());
        self.status(format!("receiving on {}", host(url)));

        let mut heartbeat = interval(PING_EVERY);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut last_seen = Instant::now();
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    if last_seen.elapsed() > IDLE_LIMIT {
                        return Err("relay stopped responding".into());
                    }
                    socket.send(Message::Ping(Vec::new())).await.map_err(|e| e.to_string())?;
                }
                frame = socket.next() => {
                    let Some(frame) = frame else { return Err("connection closed".into()) };
                    let frame = frame.map_err(|e| e.to_string())?;
                    last_seen = Instant::now();
                    let Some(value) = parse(&frame) else { continue };
                    if value["type"] == "envelope" {
                        self.consume(&mut socket, &value).await?;
                    }
                }
            }
        }
    }

    async fn consume(&self, socket: &mut Socket, value: &Value) -> Result<(), String> {
        let (Some(id), Some(ciphertext)) = (value["id"].as_str(), value["ciphertext"].as_str())
        else {
            return Ok(());
        };
        let (disposition, notices) = match B64.decode(ciphertext) {
            Ok(frame) => self.engine.lock().unwrap().receive(&frame),
            Err(_) => (Disposition::Consumed, Vec::new()),
        };
        for notice in notices {
            let _ = self.events.send(Event::Notice(notice));
        }
        // Delete the relay copy only once the engine has made it durable.
        if disposition == Disposition::Consumed {
            send(socket, json!({"type": "ack", "id": id})).await?;
        }
        self.kick(); // receipts and acknowledgements to send back
        Ok(())
    }

    // MARK: - Sending

    async fn run_outbox(self) {
        loop {
            self.dispatch_pending();
            let _ = timeout(OUTBOX_SWEEP, self.outbox_changed.notified()).await;
        }
    }

    fn dispatch_pending(&self) {
        let deposits = match self.engine.lock().unwrap().pending_deposits() {
            Ok(deposits) => deposits,
            Err(error) => {
                self.status(format!("outbox unavailable: {error}"));
                return;
            }
        };
        let live: HashSet<_> = deposits.iter().map(|d| d.item_id.clone()).collect();
        let mut in_flight = self.in_flight.lock().unwrap();
        in_flight.retain(|id, _| live.contains(id));
        for deposit in deposits {
            if in_flight
                .get(&deposit.item_id)
                .is_some_and(|sent| sent.elapsed() < RESEND_AFTER)
            {
                continue;
            }
            in_flight.insert(deposit.item_id.clone(), Instant::now());
            let sender = self.publisher(&deposit.relay_url);
            let _ = sender.send(deposit);
        }
    }

    fn publisher(&self, url: &str) -> mpsc::UnboundedSender<Deposit> {
        let mut publishers = self.publishers.lock().unwrap();
        if let Some(existing) = publishers.get(url).filter(|tx| !tx.is_closed()) {
            return existing.clone();
        }
        let (tx, rx) = mpsc::unbounded_channel();
        publishers.insert(url.to_owned(), tx.clone());
        let hub = self.clone();
        let url = url.to_owned();
        tokio::spawn(async move { hub.supervise_publisher(url, rx).await });
        tx
    }

    async fn supervise_publisher(self, url: String, mut queue: mpsc::UnboundedReceiver<Deposit>) {
        let mut backoff = Duration::from_secs(1);
        let mut held: Vec<Deposit> = Vec::new();
        loop {
            match self.serve_publisher(&url, &mut queue, &mut held).await {
                Ok(()) => return,
                Err(error) => self.status(format!("cannot deliver via {}: {error}", host(&url))),
            }
            // Let the outbox re-dispatch anything this connection never confirmed.
            {
                let mut in_flight = self.in_flight.lock().unwrap();
                for deposit in held.drain(..) {
                    in_flight.remove(&deposit.item_id);
                }
            }
            sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
            self.kick();
        }
    }

    async fn serve_publisher(
        &self,
        url: &str,
        queue: &mut mpsc::UnboundedReceiver<Deposit>,
        held: &mut Vec<Deposit>,
    ) -> Result<(), String> {
        let mut socket = connect(url).await?;
        let mut heartbeat = interval(PING_EVERY);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut last_seen = Instant::now();
        // Deposits queued while this connection was coming up.
        for deposit in held.iter() {
            publish(&mut socket, deposit).await?;
        }
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    if last_seen.elapsed() > IDLE_LIMIT {
                        return Err("relay stopped responding".into());
                    }
                    socket.send(Message::Ping(Vec::new())).await.map_err(|e| e.to_string())?;
                }
                next = queue.recv() => {
                    let Some(deposit) = next else { return Ok(()) };
                    publish(&mut socket, &deposit).await?;
                    held.push(deposit);
                }
                frame = socket.next() => {
                    let Some(frame) = frame else { return Err("connection closed".into()) };
                    let frame = frame.map_err(|e| e.to_string())?;
                    last_seen = Instant::now();
                    let Some(value) = parse(&frame) else { continue };
                    let request_id = value["request_id"].as_str().map(str::to_owned);
                    match value["type"].as_str() {
                        Some("published") => {
                            let Some(id) = request_id else { continue };
                            held.retain(|deposit| deposit.item_id != id);
                            let confirmed = self.engine.lock().unwrap().deposit_confirmed(&id);
                            self.in_flight.lock().unwrap().remove(&id);
                            if let Err(error) = confirmed {
                                self.status(format!("could not record delivery: {error}"));
                            }
                            self.kick();
                        }
                        Some("error") => {
                            let message = value["message"].as_str().unwrap_or("error").to_owned();
                            self.status(format!("{} refused a message: {message}", host(url)));
                            // Leave it in flight; it is retried after RESEND_AFTER
                            // without blocking anything queued behind it.
                            if let Some(id) = request_id {
                                held.retain(|deposit| deposit.item_id != id);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

async fn publish(socket: &mut Socket, deposit: &Deposit) -> Result<(), String> {
    send(
        socket,
        json!({
            "type": "publish",
            "recipient": hex::encode(deposit.recipient),
            "ciphertext": deposit.frame,
            "request_id": deposit.item_id,
        }),
    )
    .await
}

/// Opens a socket and negotiates the mailbox protocol range.
async fn connect(url: &str) -> Result<Socket, String> {
    let (mut socket, _) = timeout(HANDSHAKE_TIMEOUT, tokio_tungstenite::connect_async(url))
        .await
        .map_err(|_| "connection timed out".to_string())?
        .map_err(|e| e.to_string())?;
    send(
        &mut socket,
        json!({
            "type": "hello",
            "min_protocol_version": MIN_PROTOCOL,
            "max_protocol_version": MAX_PROTOCOL,
        }),
    )
    .await?;
    let reply = next_json(&mut socket).await?;
    match reply["type"].as_str() {
        Some("compatible") => Ok(socket),
        Some("incompatible") => Err(format!(
            "relay speaks protocol {}–{}, this client {MIN_PROTOCOL}–{MAX_PROTOCOL}",
            reply["min_protocol_version"], reply["max_protocol_version"]
        )),
        _ => Err("relay handshake failed".into()),
    }
}

async fn send(socket: &mut Socket, value: Value) -> Result<(), String> {
    socket
        .send(Message::Text(value.to_string()))
        .await
        .map_err(|e| e.to_string())
}

async fn expect(socket: &mut Socket, kind: &str) -> Result<Value, String> {
    let value = next_json(socket).await?;
    if value["type"] == kind {
        Ok(value)
    } else {
        Err(format!(
            "expected {kind}, relay said {}",
            value["message"]
                .as_str()
                .unwrap_or(value["type"].as_str().unwrap_or("?"))
        ))
    }
}

/// Reads the next JSON frame within the handshake deadline.
async fn next_json(socket: &mut Socket) -> Result<Value, String> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let frame = timeout(remaining, socket.next())
            .await
            .map_err(|_| "relay did not answer".to_string())?
            .ok_or("connection closed")?
            .map_err(|e| e.to_string())?;
        if let Some(value) = parse(&frame) {
            return Ok(value);
        }
    }
}

fn parse(frame: &Message) -> Option<Value> {
    match frame {
        Message::Text(text) => serde_json::from_str(text).ok(),
        Message::Binary(bytes) => serde_json::from_slice(bytes).ok(),
        _ => None,
    }
}

pub fn host(url: &str) -> &str {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .unwrap_or(url)
}
