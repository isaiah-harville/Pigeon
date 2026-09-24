# Relay Module Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize `pigeon-relay` into explicit mailbox, group, coordinator, push, configuration, and application-composition modules while preserving every public route and wire encoding.

**Architecture:** Keep one relay binary and compose three independently owned ciphertext services in `app.rs`. Each service owns its configuration and mutable state; the group WebSocket handler receives group and coordinator handles because those protocols share a route, but their stores and authorization logic remain separate.

**Tech Stack:** Rust 2021, axum, tokio, serde/serde_json, ed25519-dalek, existing in-memory stores and APNs client.

**Spec:** `docs/superpowers/specs/2026-08-25-relay-module-architecture-design.md`

## Global Constraints

- Preserve `/ws`, `/group/ws`, `/healthz`, and every serialized client/server message shape.
- Preserve all existing environment-variable names and defaults.
- An explicitly invalid environment value must fail startup; a default applies only when the variable is absent.
- Keep mailbox, group-message, and coordinator storage independent.
- Never log secret seeds, addresses, capabilities, ciphertext, or push tokens.
- Keep all mutex acquisition local and non-nested.
- Do not add generic service traits, another crate, another process, or another route.

---

### Task 1: Validated Configuration and Thin Bootstrap

**Files:**
- Create: `pigeon-relay/src/config.rs`
- Create: `pigeon-relay/src/clock.rs`
- Create: `pigeon-relay/src/app.rs`
- Modify: `pigeon-relay/src/main.rs`
- Test: `pigeon-relay/src/config.rs`
- Test: `pigeon-relay/src/app.rs`

**Interfaces:**
- Produces: `RelayConfig::from_env() -> Result<RelayConfig, ConfigError>`.
- Produces: `RelayConfig::from_lookup(F) -> Result<RelayConfig, ConfigError>` for deterministic unit tests, where `F: FnMut(&str) -> Option<String>`.
- Produces: `clock::now() -> u64`.
- Produces: `app::build(config: RelayConfig) -> Result<(Router, AppState), AppError>` and `app::run_expiry(AppState)`.

- [ ] **Step 1: Add failing configuration tests**

```rust
#[test]
fn absent_values_use_documented_defaults() {
    let config = RelayConfig::from_lookup(|_| None).unwrap();
    assert_eq!(config.bind_addr, "0.0.0.0:8080");
    assert_eq!(config.mailbox.ttl_secs, 30 * 24 * 3600);
    assert_eq!(config.group.max_capabilities_per_group, 128);
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
```

- [ ] **Step 2: Run the targeted tests and confirm they fail**

Run: `cargo test --manifest-path pigeon-relay/Cargo.toml config::tests`

Expected: FAIL because `RelayConfig` does not exist.

- [ ] **Step 3: Implement typed configuration and clock modules**

```rust
pub struct RelayConfig {
    pub bind_addr: String,
    pub mailbox: mailbox::Config,
    pub group: group::Config,
    pub coordinator: coordinator::Config,
    pub apns_min_interval: Duration,
}

impl RelayConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self, ConfigError> {
        // Parse every existing PIGEON_RELAY_*, PIGEON_GROUP_*,
        // PIGEON_COORDINATOR_*, and PIGEON_APNS_MIN_INTERVAL_SECS value.
        // Reject parse failures, usize overflow, and zero bounds.
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
```

- [ ] **Step 4: Extract router construction and expiry orchestration into `app.rs`**

```rust
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/healthz", get(health))
        .route("/ws", get(mailbox::connection::ws_handler))
        .route("/group/ws", get(group::connection::ws_handler))
        .with_state(state)
}
```

Keep `main.rs` limited to configuration, state construction, expiry-task spawn,
listener binding, and `axum::serve`. Preserve the content-free startup log.

- [ ] **Step 5: Run targeted tests**

Run: `cargo test --manifest-path pigeon-relay/Cargo.toml config::tests app::tests`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pigeon-relay/src/config.rs pigeon-relay/src/clock.rs pigeon-relay/src/app.rs pigeon-relay/src/main.rs
git commit -m "refactor(relay): isolate configuration and bootstrap"
```

### Task 2: Mailbox Service Boundary

**Files:**
- Create: `pigeon-relay/src/mailbox/mod.rs`
- Move: `pigeon-relay/src/connection.rs` to `pigeon-relay/src/mailbox/connection.rs`
- Move: `pigeon-relay/src/protocol.rs` to `pigeon-relay/src/mailbox/protocol.rs`
- Replace: `pigeon-relay/src/mailbox.rs` with `pigeon-relay/src/mailbox/store.rs`
- Move: `pigeon-relay/src/tests.rs` to `pigeon-relay/src/mailbox/tests.rs`
- Modify: `pigeon-relay/src/app.rs`

**Interfaces:**
- Produces: `mailbox::Service { store: Arc<Mutex<Store>>, config: Config }`.
- Produces: `Service::expire(cutoff: u64)`.
- Consumes: shared `Arc<AtomicU64>` connection counter and `Arc<PushRegistry>` through `AppState`, without owning group or coordinator state.

- [ ] **Step 1: Add a failing service-isolation test**

```rust
#[test]
fn service_expiry_only_mutates_mailboxes() {
    let service = Service::new(Config::for_test());
    service.store.lock().unwrap().deposit(
        TEST_ADDRESS,
        StoredEnvelope { id: "1".into(), ciphertext: "x".into(), ts: 1 },
        &service.config,
    );
    service.expire(2);
    assert_eq!(service.store.lock().unwrap().len(), 0);
}
```

- [ ] **Step 2: Run the mailbox test and confirm it fails**

Run: `cargo test --manifest-path pigeon-relay/Cargo.toml mailbox::tests::service_expiry_only_mutates_mailboxes`

Expected: FAIL because `mailbox::Service` does not exist.

- [ ] **Step 3: Move mailbox code and introduce the service owner**

```rust
#[derive(Clone)]
pub struct Service {
    pub(crate) store: Arc<Mutex<Store>>,
    pub(crate) config: Config,
}

impl Service {
    pub fn new(config: Config) -> Self;
    pub fn expire(&self, cutoff: u64);
}
```

Update paths to `crate::mailbox::{protocol, store}`. Keep address validation,
deposit fairness, bounded subscriber channels, acknowledgement, and expiry
semantics byte-for-byte compatible.

- [ ] **Step 4: Narrow mailbox connection state access**

The `/ws` handler may access only `state.mailbox`, `state.push`, and
`state.connection_ids`. Remove direct access to group and coordinator fields.

- [ ] **Step 5: Run mailbox and full relay tests**

Run: `cargo test --manifest-path pigeon-relay/Cargo.toml mailbox::tests`

Run: `cargo test --manifest-path pigeon-relay/Cargo.toml`

Expected: PASS with unchanged mailbox protocol fixtures.

- [ ] **Step 6: Commit**

```bash
git add pigeon-relay/src/mailbox pigeon-relay/src/app.rs pigeon-relay/src/main.rs
git commit -m "refactor(relay): isolate mailbox service"
```

### Task 3: Group and Coordinator Service Boundaries

**Files:**
- Create: `pigeon-relay/src/group/mod.rs`
- Move: `pigeon-relay/src/group_connection.rs` to `pigeon-relay/src/group/connection.rs`
- Move: `pigeon-relay/src/group_protocol.rs` to `pigeon-relay/src/group/protocol.rs`
- Move: `pigeon-relay/src/group_store.rs` to `pigeon-relay/src/group/store.rs`
- Move: `pigeon-relay/src/group_tests.rs` to `pigeon-relay/src/group/tests.rs`
- Create: `pigeon-relay/src/coordinator/mod.rs`
- Create: `pigeon-relay/src/coordinator/protocol.rs`
- Move: `pigeon-relay/src/coordinator_store.rs` to `pigeon-relay/src/coordinator/store.rs`
- Move: `pigeon-relay/src/coordinator_tests.rs` to `pigeon-relay/src/coordinator/tests.rs`
- Modify: `pigeon-relay/src/app.rs`

**Interfaces:**
- Produces: `group::Service { store, subscribers }` and `Service::expire(now: u64)`.
- Produces: `coordinator::Service { store }` and `Service::expire(now: u64)`.
- Produces: coordinator wire DTOs from `coordinator::protocol`, referenced by the existing tagged enums in `group::protocol` without changing JSON.
- Consumes: the group WebSocket handler receives `state.group`, `state.coordinator`, `state.push`, and `state.connection_ids` only.

- [ ] **Step 1: Add failing independent-expiry tests**

```rust
#[test]
fn group_and_coordinator_expire_independently() {
    let group = group::Service::new(group::Config::for_test());
    let coordinator = coordinator::Service::new(
        coordinator::Config::for_test(),
        test_signing_key(),
    );
    seed_expired_group_entry(&group);
    seed_live_candidate(&coordinator);
    group.expire(100);
    assert!(group.store.lock().unwrap().is_empty());
    assert_eq!(coordinator.store.lock().unwrap().candidate_count(), 1);
}
```

- [ ] **Step 2: Run the isolation test and confirm it fails**

Run: `cargo test --manifest-path pigeon-relay/Cargo.toml app::tests::group_and_coordinator_expire_independently`

Expected: FAIL because the services are not independently owned.

- [ ] **Step 3: Move group code and create `group::Service`**

```rust
#[derive(Clone)]
pub struct Service {
    pub(crate) store: Arc<Mutex<Store>>,
    pub(crate) subscribers: Arc<Mutex<HashMap<[u8; 32], Vec<Subscriber>>>>,
}

impl Service {
    pub fn new(config: Config) -> Self;
    pub fn expire(&self, now: u64);
}
```

The store retains its config internally. Preserve registration signatures,
challenge authentication, append/read/control capability checks, cursor rules,
all-reader retention, duplicate append handling, revocation, rotation, and Wake
messages.

- [ ] **Step 4: Move coordinator code and create `coordinator::Service`**

```rust
#[derive(Clone)]
pub struct Service {
    pub(crate) store: Arc<Mutex<Store>>,
}

impl Service {
    pub fn new(config: Config, signer: SigningKey) -> Self;
    pub fn expire(&self, now: u64);
}
```

Move coordinator-specific receipt and candidate DTOs into
`coordinator/protocol.rs`. Have `group::protocol::{ClientMsg, ServerMsg}` refer
to those DTOs so serde tags and fields remain unchanged.

- [ ] **Step 5: Narrow group connection state access and avoid nested locks**

For each request: authenticate using the relevant service, release that store
lock, then send subscriber wakes or invoke push. Never retain the group lock
while acquiring coordinator, subscribers, or push state.

- [ ] **Step 6: Run subsystem and relay tests**

Run: `cargo test --manifest-path pigeon-relay/Cargo.toml group::tests`

Run: `cargo test --manifest-path pigeon-relay/Cargo.toml coordinator::tests`

Run: `cargo test --manifest-path pigeon-relay/Cargo.toml`

Expected: PASS with unchanged JSON protocol fixtures and receipt signatures.

- [ ] **Step 7: Commit**

```bash
git add pigeon-relay/src/group pigeon-relay/src/coordinator pigeon-relay/src/app.rs pigeon-relay/src/main.rs
git commit -m "refactor(relay): separate group service state"
```

### Task 4: Push Module and Architecture Verification

**Files:**
- Move: `pigeon-relay/src/push.rs` to `pigeon-relay/src/push/mod.rs`
- Modify: `pigeon-relay/src/app.rs`
- Modify: `pigeon-relay/src/main.rs`
- Test: `pigeon-relay/src/app.rs`

**Interfaces:**
- Preserves: `push::PushRegistry`, `push::ApnsGateway`, registration authorization, rate limiting, and content-free payloads.
- Produces: final `AppState { mailbox, group, coordinator, push, connection_ids }` with no generic store fields.

- [ ] **Step 1: Add an application composition test**

```rust
#[tokio::test]
async fn router_preserves_public_routes() {
    let app = router(AppState::for_test());
    assert_eq!(request(&app, "/healthz").await.status(), StatusCode::OK);
    assert_ne!(request(&app, "/ws").await.status(), StatusCode::NOT_FOUND);
    assert_ne!(request(&app, "/group/ws").await.status(), StatusCode::NOT_FOUND);
}
```

- [ ] **Step 2: Move the push module and finish `AppState` composition**

```rust
#[derive(Clone)]
pub struct AppState {
    pub(crate) mailbox: mailbox::Service,
    pub(crate) group: group::Service,
    pub(crate) coordinator: coordinator::Service,
    pub(crate) push: Arc<PushRegistry>,
    pub(crate) connection_ids: Arc<AtomicU64>,
}
```

Remove obsolete flat modules and the old god-state. Update crate-level docs to
describe the actual source tree and security boundaries.

- [ ] **Step 3: Run focused verification**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --manifest-path pigeon-relay/Cargo.toml --all-targets -- -D warnings`

Run: `cargo test --manifest-path pigeon-relay/Cargo.toml`

Expected: all commands exit 0.

- [ ] **Step 4: Run repository-wide verification**

Run: `cargo clippy --workspace --all-targets -- -D warnings`

Run: `cargo test --workspace`

Run: `cargo deny check advisories licenses bans sources`

Run: `cargo build --release --manifest-path pigeon-relay/Cargo.toml`

Run: `git diff --check`

Expected: all commands exit 0. Confirm `git status --short` contains no generated
XCFramework or Swift binding artifacts.

- [ ] **Step 5: Commit**

```bash
git add pigeon-relay/src
git commit -m "refactor(relay): finalize protocol-oriented layout"
```
