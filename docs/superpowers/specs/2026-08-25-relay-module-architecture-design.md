# Relay Module Architecture

## Scope

Reorganize `pigeon-relay` around its protocol boundaries without changing its
wire formats, routes, retention rules, or zero-knowledge security model. The
crate remains one deployable binary. This refactor covers the relay only; it
does not introduce generic service frameworks or split the relay into multiple
crates or processes.

## Architecture

The relay has three independent ciphertext services and one shared optional
push facility:

- `mailbox`: identity-addressed pairwise ciphertext deposit, delivery, and
  acknowledgement on `/ws`.
- `group`: capability-authorized ordered group ciphertext storage and delivery
  on `/group/ws`.
- `coordinator`: capability-authorized MLS candidate sequencing and signed
  receipts, carried on the group WebSocket but stored independently from group
  messages.
- `push`: opt-in APNs wake registration and content-free wake delivery shared by
  mailbox and group services.

The source tree will be:

```text
pigeon-relay/src/
  main.rs
  app.rs
  config.rs
  clock.rs
  mailbox/
    mod.rs
    connection.rs
    protocol.rs
    store.rs
    tests.rs
  group/
    mod.rs
    connection.rs
    protocol.rs
    store.rs
    tests.rs
  coordinator/
    mod.rs
    store.rs
    tests.rs
  push/
    mod.rs
```

`main.rs` is limited to process startup: load configuration, construct the
application, bind the listener, and serve it. `app.rs` owns router construction,
application composition, and periodic expiry. `config.rs` parses and validates
environment configuration into subsystem-specific values. `clock.rs` contains
the system clock adapter used by production code.

## State Ownership

Each service owns its store, configuration, and live subscribers. Application
state composes service handles plus explicitly shared dependencies such as the
push registry and connection-ID allocator. A connection handler receives the
narrowest state that supports its protocol; stores from another subsystem are
not exposed through its interface.

The group connection handler may invoke both the group and coordinator services
because both protocols share `/group/ws`. That transport-level composition does
not merge their storage or authorization logic. Coordinator receipts remain
signed by the configured relay coordinator key, while group entries remain
opaque and unsigned by the relay.

All mutex acquisition remains local and non-nested. No service calls another
while holding a store lock. This avoids hidden lock ordering and keeps each
state machine independently testable.

## Configuration and Failure Handling

Environment parsing is centralized. Invalid explicitly supplied values fail
startup instead of silently falling back to defaults. Defaults apply only when
a variable is absent. Size conversions are checked, and each subsystem
validates nonzero and internally consistent limits.

Release deployments require a stable coordinator signing seed. Debug builds may
generate an ephemeral development key when the variable is absent. Secret seed
material, mailbox addresses, capabilities, and ciphertext are never logged.

Protocol errors remain explicit client responses where the existing wire
contract permits them. Internal poisoned-lock or server failures close the
connection without exposing sensitive state.

## Compatibility and Testing

The refactor preserves `/ws`, `/group/ws`, all serialized message shapes, and
the existing environment-variable names. Tests move next to the subsystem they
exercise. Store tests remain deterministic by supplying timestamps directly;
connection tests cover the routed protocol boundary. Additional tests cover
configuration rejection, router construction, and continued storage isolation
between group messages and coordinator candidates.

Verification requires formatting, clippy with warnings denied, the full Rust
workspace test suite, dependency policy checks, and a release build of the relay.
