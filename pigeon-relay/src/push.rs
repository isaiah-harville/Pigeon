// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Opt-in APNs wake-up gateway for the **official** Pigeon relay.
//!
//! Relay delivery is otherwise WebSocket-pull only: to receive, a recipient's
//! app must be running and holding an authenticated subscription to its mailbox.
//! APNs is the only Apple-sanctioned way to wake a suspended or terminated app,
//! and an APNs push to the Pigeon bundle id can only be signed by the holder of
//! the app's APNs `.p8` key — the app publisher. So this gateway lives only on
//! the official relay; self-hosted and third-party relays leave it unconfigured
//! and simply don't push (best-effort background reception, exactly as before).
//!
//! Privacy posture (documented in SECURITY_MODEL §6.1): the push is
//! **content-free** — a fixed visible alert that only wakes the app, with no
//! sender, content, or count. The app then drains its mailbox and decrypts on
//! unlock through the existing pipeline; messages never traverse Apple in
//! readable form. The gateway does learn `device token ↔ "this mailbox has mail
//! at time T"`, which is more metadata than the blind relay alone — hence opt-in,
//! and only on the official deployment. Tokens live in memory only (like every
//! other relay state); clients re-register after each authenticated subscribe.
//!
//! A device token is bound to a mailbox only after that connection has proven
//! ownership of the mailbox (the `Subscribe → Challenge → Auth` handshake), so a
//! token can only ever be attached to a mailbox by that mailbox's key holder. No
//! new trust path is introduced.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;

/// Upper bound on an APNs device token (hex). Classic tokens are 32 bytes (64
/// hex chars); modern tokens are larger, so this is generously above any real
/// token while still bounding memory against junk registrations.
const MAX_TOKEN_LEN: usize = 200;

/// The entire push payload: a fixed, visible alert that carries no sender,
/// content, or count — just a generic prompt to open the app. A *visible* alert
/// (not a silent `content-available` background push) is deliberate — iOS
/// withholds silent pushes after the user force-quits the app, so only a visible
/// alert reliably reaches a terminated app.
const PUSH_PAYLOAD: &str =
    r#"{"aps":{"alert":{"title":"New message","body":"Open Pigeon to read your message."}}}"#;

/// An APNs provider JWT is valid for up to an hour; refresh comfortably inside
/// that so a cached token never expires mid-flight.
const JWT_TTL: Duration = Duration::from_secs(50 * 60);

/// Whether `token` is a syntactically plausible APNs device token (non-empty
/// hex within bounds). The relay never decodes it further.
pub fn is_valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_LEN
        && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// What to do with a token after an APNs send attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum PushOutcome {
    /// APNs accepted the push.
    Delivered,
    /// The token is no longer valid (device unregistered); drop it.
    Unregister,
    /// Transient or configuration failure; keep the token and try again later.
    Failed,
}

/// Maps an APNs HTTP status to an action. Conservative on purpose: only `410`
/// (the device token is no longer active) drops a token. A `400` can mean a
/// misconfigured topic just as easily as a bad token, so we keep the token
/// rather than risk mass-evicting valid ones on an operator mistake.
pub fn classify_apns_status(status: u16) -> PushOutcome {
    match status {
        200 => PushOutcome::Delivered,
        410 => PushOutcome::Unregister,
        _ => PushOutcome::Failed,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Token registry
// ---------------------------------------------------------------------------

/// Per-mailbox device tokens plus the coalescing clock, and the (optional) APNs
/// gateway. When `gateway` is `None` (self-hosted / third-party relays) the
/// registry refuses registrations and never pushes.
pub struct PushRegistry {
    /// mailbox hex → device tokens (one user may have several devices).
    tokens: Mutex<HashMap<String, HashSet<String>>>,
    /// mailbox hex → last time we pushed it, for coalescing bursts.
    last_push: Mutex<HashMap<String, Instant>>,
    /// Minimum gap between pushes to the same mailbox. A burst of deposits wakes
    /// the app once; it drains everything in that one wake.
    min_interval: Duration,
    gateway: Option<ApnsGateway>,
}

impl PushRegistry {
    pub fn new(gateway: Option<ApnsGateway>, min_interval: Duration) -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            last_push: Mutex::new(HashMap::new()),
            min_interval,
            gateway,
        }
    }

    /// Whether this relay can actually push (an APNs gateway is configured).
    pub fn enabled(&self) -> bool {
        self.gateway.is_some()
    }

    /// Binds `token` to `mailbox`. The caller must have already verified the
    /// connection owns `mailbox`.
    pub fn register(&self, mailbox: &str, token: String) {
        self.tokens
            .lock()
            .unwrap()
            .entry(mailbox.to_string())
            .or_default()
            .insert(token);
    }

    /// Removes `token` from `mailbox` (opt-out / rotation), reclaiming the entry
    /// when its last token is gone.
    pub fn unregister(&self, mailbox: &str, token: &str) {
        let mut map = self.tokens.lock().unwrap();
        if let Some(set) = map.get_mut(mailbox) {
            set.remove(token);
            if set.is_empty() {
                map.remove(mailbox);
            }
        }
    }

    fn tokens_for(&self, mailbox: &str) -> Vec<String> {
        self.tokens
            .lock()
            .unwrap()
            .get(mailbox)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns true (and records `now` as the last push) iff the coalescing
    /// window for `mailbox` has elapsed. Split from wall-clock so it is testable.
    fn should_push_at(&self, mailbox: &str, now: Instant) -> bool {
        let mut last = self.last_push.lock().unwrap();
        match last.get(mailbox) {
            Some(t) if now.duration_since(*t) < self.min_interval => false,
            _ => {
                last.insert(mailbox.to_string(), now);
                true
            }
        }
    }
}

/// Wakes `mailbox` after a deposit, if push is enabled, the mailbox has a
/// registered token, and the coalescing window has elapsed. Non-blocking: the
/// actual APNs round-trips run on a detached task so `publish` never waits on
/// the network (and never holds a mailbox lock across it).
pub fn notify_deposit(registry: Arc<PushRegistry>, mailbox: String) {
    if !registry.enabled() {
        return;
    }
    let tokens = registry.tokens_for(&mailbox);
    if tokens.is_empty() {
        return;
    }
    if !registry.should_push_at(&mailbox, Instant::now()) {
        return;
    }
    tokio::spawn(async move {
        push_all(&registry, &mailbox, tokens).await;
    });
}

async fn push_all(registry: &PushRegistry, mailbox: &str, tokens: Vec<String>) {
    let Some(gateway) = &registry.gateway else {
        return;
    };
    let mut dead = Vec::new();
    for token in tokens {
        if gateway.send(&token).await == PushOutcome::Unregister {
            dead.push(token);
        }
    }
    for token in dead {
        registry.unregister(mailbox, &token);
    }
}

// ---------------------------------------------------------------------------
// APNs HTTP/2 client
// ---------------------------------------------------------------------------

/// Provider-token (JWT) claims for APNs: issuer is the Apple team id, issued-at
/// is now. Apple keys the rest off the JWT header's `kid` and the request topic.
#[derive(Serialize)]
struct Claims {
    iss: String,
    iat: u64,
}

struct CachedJwt {
    token: String,
    created: Instant,
}

/// The signed, content-free APNs sender for the official deployment. Holds the
/// `.p8` signing key (as a `jsonwebtoken` key) and a cached provider JWT.
pub struct ApnsGateway {
    client: reqwest::Client,
    team_id: String,
    key_id: String,
    /// APNs topic — the app's bundle id.
    topic: String,
    /// APNs host (`api.push.apple.com`, or `api.sandbox.push.apple.com` for dev).
    host: String,
    encoding_key: EncodingKey,
    jwt: Mutex<Option<CachedJwt>>,
}

impl ApnsGateway {
    /// Builds the gateway from the environment, or returns `None` if it isn't
    /// fully configured (the common case: any relay that isn't the official one).
    /// Never logs key material.
    pub fn from_env() -> Option<Self> {
        let team_id = std::env::var("PIGEON_APNS_TEAM_ID").ok()?;
        let key_id = std::env::var("PIGEON_APNS_KEY_ID").ok()?;
        let topic = std::env::var("PIGEON_APNS_TOPIC").ok()?;
        let key_path = std::env::var("PIGEON_APNS_KEY_PATH").ok()?;
        let host =
            std::env::var("PIGEON_APNS_HOST").unwrap_or_else(|_| "api.push.apple.com".into());

        let pem = std::fs::read(&key_path)
            .map_err(|e| eprintln!("pigeon-relay: cannot read APNS key: {e}"))
            .ok()?;
        let encoding_key = EncodingKey::from_ec_pem(&pem)
            .map_err(|_| eprintln!("pigeon-relay: APNS key is not a valid EC .p8"))
            .ok()?;
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| eprintln!("pigeon-relay: cannot build HTTP client: {e}"))
            .ok()?;

        Some(Self {
            client,
            team_id,
            key_id,
            topic,
            host,
            encoding_key,
            jwt: Mutex::new(None),
        })
    }

    /// A bundle-id topic and host, for a non-secret startup log line.
    pub fn describe(&self) -> String {
        format!("topic={}, host={}", self.topic, self.host)
    }

    /// Returns a valid provider JWT, minting (and caching) a fresh one when the
    /// cache is empty or older than [`JWT_TTL`].
    fn provider_jwt(&self) -> Result<String, jsonwebtoken::errors::Error> {
        let mut cache = self.jwt.lock().unwrap();
        if let Some(cached) = cache.as_ref() {
            if cached.created.elapsed() < JWT_TTL {
                return Ok(cached.token.clone());
            }
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let claims = Claims {
            iss: self.team_id.clone(),
            iat: now_secs(),
        };
        let token = encode(&header, &claims, &self.encoding_key)?;
        *cache = Some(CachedJwt {
            token: token.clone(),
            created: Instant::now(),
        });
        Ok(token)
    }

    /// Sends the content-free alert to one device token.
    async fn send(&self, token: &str) -> PushOutcome {
        let Ok(jwt) = self.provider_jwt() else {
            return PushOutcome::Failed;
        };
        let url = format!("https://{}/3/device/{}", self.host, token);
        let resp = self
            .client
            .post(&url)
            .header("authorization", format!("bearer {jwt}"))
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("content-type", "application/json")
            .body(PUSH_PAYLOAD)
            .send()
            .await;
        match resp {
            Ok(r) => classify_apns_status(r.status().as_u16()),
            Err(_) => PushOutcome::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> PushRegistry {
        // No gateway: exercises the store/coalescing logic without a network.
        PushRegistry::new(None, Duration::from_secs(30))
    }

    #[test]
    fn valid_token_requires_nonempty_bounded_hex() {
        assert!(is_valid_token("00aabb"));
        assert!(!is_valid_token("")); // empty
        assert!(!is_valid_token("zz")); // not hex
        assert!(!is_valid_token(&"a".repeat(MAX_TOKEN_LEN + 1))); // too long
    }

    #[test]
    fn register_and_unregister_track_tokens() {
        let r = registry();
        r.register("mb", "aa".into());
        r.register("mb", "bb".into());
        r.register("mb", "aa".into()); // idempotent
        let mut tokens = r.tokens_for("mb");
        tokens.sort();
        assert_eq!(tokens, vec!["aa".to_string(), "bb".to_string()]);

        r.unregister("mb", "aa");
        assert_eq!(r.tokens_for("mb"), vec!["bb".to_string()]);
        r.unregister("mb", "bb");
        assert!(r.tokens_for("mb").is_empty());
        // Last token gone reclaims the mailbox entry.
        assert!(r.tokens.lock().unwrap().get("mb").is_none());
    }

    #[test]
    fn coalescing_suppresses_pushes_inside_the_window() {
        let r = registry();
        let t0 = Instant::now();
        assert!(r.should_push_at("mb", t0)); // first push allowed
        assert!(!r.should_push_at("mb", t0 + Duration::from_secs(5))); // within 30s
        assert!(r.should_push_at("mb", t0 + Duration::from_secs(31))); // window elapsed
    }

    #[test]
    fn classify_only_drops_token_on_410() {
        assert_eq!(classify_apns_status(200), PushOutcome::Delivered);
        assert_eq!(classify_apns_status(410), PushOutcome::Unregister);
        assert_eq!(classify_apns_status(400), PushOutcome::Failed);
        assert_eq!(classify_apns_status(429), PushOutcome::Failed);
        assert_eq!(classify_apns_status(500), PushOutcome::Failed);
    }
}
