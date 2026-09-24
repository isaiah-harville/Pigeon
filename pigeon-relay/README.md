# Pigeon Relay

A **zero-knowledge, federated ciphertext relay** — the optional internet path
for Pigeon. One deployment hosts pairwise mailboxes, authenticated opaque group
mailboxes, and the group's signed MLS commit coordinator.

It is deliberately dumb. It stores and forwards opaque ciphertext blobs
addressed by a recipient's public key. It **cannot read messages**, holds no
keys, keeps no accounts, and logs no addresses or content. Confidentiality,
authentication, integrity, forward secrecy, and the safety-number trust check
are all enforced end-to-end by Pigeon clients, *below* this layer. A compromised
relay yields metadata (who connects, when) and the ability to drop/delay
ciphertext — never plaintext or a forged session.

See [`SECURITY_MODEL.md`](../docs/SECURITY_MODEL.md) §6.1 for the full
threat model and why remote delivery cannot be serverless.

## Run it

```sh
docker run -p 8080:8080 \
  -e PIGEON_COORDINATOR_SIGNING_SEED_HEX="<64-hex-character-secret>" \
  ghcr.io/<owner>/pigeon-relay:latest
```

The image is multi-arch (amd64/arm64), distroless, non-root, and keeps message
state only in memory. Point your homelab Kubernetes / Compose / VPS at it and
terminate TLS at your ingress (clients use `wss://`). The coordinator seed is
required in release builds, must be generated from a cryptographically secure
source, and must remain stable across restarts. Store it in a secret manager;
never put it in an image, manifest, shell history, or logs.

### Configuration (environment)

| Variable                        | Default          | Meaning                                        |
| ------------------------------- | ---------------- | ---------------------------------------------- |
| `PIGEON_RELAY_ADDR`             | `0.0.0.0:8080`   | Listen address.                                |
| `PIGEON_RELAY_TTL_SECS`         | `2592000` (30d)  | How long an undelivered envelope is kept.      |
| `PIGEON_RELAY_MAX_QUEUE`        | `1000`           | Max envelopes retained per mailbox.            |
| `PIGEON_RELAY_MAX_MAILBOXES`    | `10000`          | Max mailboxes held at once.                    |
| `PIGEON_RELAY_MAX_TOTAL_BYTES`  | `536870912`      | Hard ceiling on total stored ciphertext.       |
| `PIGEON_GROUP_TTL_SECS`         | `2592000` (30d)  | Group entry and registration lifetime.         |
| `PIGEON_GROUP_MAX_GROUPS`       | `10000`          | Maximum registered groups.                     |
| `PIGEON_GROUP_MAX_CAPABILITIES` | `128`            | Maximum capabilities in one group.             |
| `PIGEON_GROUP_MAX_ENTRY_BYTES`  | `1048576`        | Maximum opaque group entry.                    |
| `PIGEON_GROUP_MAX_ENTRIES`      | `10000`          | Maximum entries retained per group.            |
| `PIGEON_GROUP_MAX_TOTAL_BYTES`  | `536870912`      | Hard ceiling for all group ciphertext.         |
| `PIGEON_GROUP_MAX_FETCH_BYTES`  | `4194304`        | Maximum group fetch response.                  |
| `PIGEON_COORDINATOR_MAX_PER_EPOCH` | `256`         | Candidate attempts retained per epoch.         |
| `PIGEON_COORDINATOR_MAX_CANDIDATE_BYTES` | `1048576` | Maximum opaque MLS candidate.              |
| `PIGEON_COORDINATOR_MAX_TOTAL_BYTES` | `268435456` | Hard ceiling for coordinator candidates.     |
| `PIGEON_COORDINATOR_MAX_FETCH_BYTES` | `4194304`  | Maximum coordinator fetch response.            |
| `PIGEON_COORDINATOR_TTL_SECS`   | `2592000` (30d)  | Coordinator candidate lifetime.                |
| `PIGEON_COORDINATOR_SIGNING_SEED_HEX` | — (required in release) | Stable 32-byte Ed25519 seed, hex encoded. |

Deposits are unauthenticated, so the last two are the abuse bound. Past
`MAX_MAILBOXES` a deposit to a *new* address is refused (existing mailboxes keep
working); past `MAX_TOTAL_BYTES` each deposit evicts the oldest envelope from
whichever mailbox is holding the most, so a flooding address pays for its own
pressure instead of evicting everyone else's mail.

Storage is **in-memory and ephemeral** by design — a relay is a transient
rendezvous, not durable storage. The coordinator identity is the exception: its
signing seed is supplied by the operator and must survive restarts. Clients
authenticate that public key before selecting the deployment for a group.

### APNs push gateway (official deployment only)

Optional, and only meaningful for the **official** Pigeon relay — an APNs push to
the Pigeon bundle id can only be signed by the holder of the app's `.p8` key, so
push **cannot be federated**. Leave these unset (the default) and the relay never
pushes; it refuses `register_push` and behaves exactly as before. Set **all four**
required vars to enable a content-free wake-up alert on deposit. See
[SECURITY_MODEL.md §6.1](../docs/SECURITY_MODEL.md) for the metadata tradeoff.

| Variable                       | Default              | Meaning                                              |
| ------------------------------ | -------------------- | ---------------------------------------------------- |
| `PIGEON_APNS_TEAM_ID`          | —                    | Apple Developer team id (JWT `iss`). **Required.**   |
| `PIGEON_APNS_KEY_ID`           | —                    | APNs auth-key id (JWT `kid`). **Required.**          |
| `PIGEON_APNS_TOPIC`            | —                    | App bundle id (APNs topic). **Required.**            |
| `PIGEON_APNS_KEY_PATH`         | —                    | Path to the `.p8` auth key (PEM). **Required.**      |
| `PIGEON_APNS_HOST`             | `api.push.apple.com` | Use `api.sandbox.push.apple.com` for development.    |
| `PIGEON_APNS_MIN_INTERVAL_SECS`| `30`                 | Min gap between pushes to one mailbox (coalescing).  |

The `.p8` is a secret: mount it read-only and keep it out of images and logs. The
gateway holds only device tokens (in memory, like every other relay state); it
never sees plaintext, and the push payload carries no sender, content, or count.

## Federation

Relays are independent and **never talk to each other** — federation needs no
server-to-server protocol. A user advertises the relay URL(s) they can be
reached at (carried in their contact bundle / QR). To reach a peer, a sender
deposits ciphertext on *that peer's* advertised relays; the peer reads its own
mailbox from the same relays. Anyone can run one; users choose which to trust. No central party.

## Protocol

Pairwise WebSocket traffic uses `GET /ws`; group messaging and coordination use
`GET /group/ws`. Both protocols use bounded JSON frames. Addresses, group
coordination IDs, capability IDs, cursors, sizes, timing, and client IPs are
relay-visible metadata. Message and MLS candidate bodies remain opaque.

Health: `GET /healthz` → `ok`.

Every WebSocket must negotiate the relay protocol before any mailbox operation:

```json
{ "type": "hello", "min_protocol_version": 1, "max_protocol_version": 1 }
← { "type": "compatible", "protocol_version": 1 }
```

The relay selects the highest overlapping version. A disjoint range receives an
`incompatible` response containing the relay's minimum and maximum, and the
connection cannot publish, subscribe, authenticate, or acknowledge messages.

**Deposit (sender, no auth — sender is anonymous to the relay):**

```json
{ "type": "publish", "recipient": "<hex pubkey>", "ciphertext": "<base64>" }
→ { "type": "published", "id": "<id>" }
```

**Read your mailbox (recipient, must prove key ownership):**

```json
{ "type": "subscribe", "mailbox": "<hex pubkey>" }
← { "type": "challenge", "nonce": "<base64>" }
{ "type": "auth", "signature": "<base64 Ed25519 sig over the nonce bytes>" }
← { "type": "ok", "detail": "authenticated" }
← { "type": "envelope", "id": "...", "ciphertext": "<base64>", "ts": 1718500000 }
   …(queued, then live as they arrive)…
{ "type": "ack", "id": "<id>" }     // deletes the envelope
```

**Push wake-up (recipient, after auth; official relay only):**

```json
{ "type": "register_push", "token": "<hex APNs device token>" }
← { "type": "ok", "detail": "push registered" }
{ "type": "unregister_push", "token": "<hex APNs device token>" }  // opt-out / rotation
← { "type": "ok", "detail": "push unregistered" }
```

Only honored on an **authenticated** connection (so a token is bound to a mailbox
solely by that mailbox's key holder) and only when an APNs gateway is configured;
otherwise the relay replies `{ "type": "error", "message": "push not supported" }`.

The challenge–response means the relay only ever learns *public* keys (which are
the addresses anyway), and only the holder of a mailbox's private key can drain
it. Delivery is at-least-once; Pigeon clients deduplicate at the mesh layer.

Group connections separately negotiate protocol version 5 and authenticate a
group-scoped capability challenge. A canonical registration atomically replaces
the complete capability set, which revokes removed members without exposing the
roster's root identities. The coordinator orders opaque candidates and signs an
append-only receipt chain; clients still validate every MLS commit and policy
transition end to end. The service cannot decrypt, authorize, or forge a group
transition, but it can observe group-level metadata and can delay or deny
progress.

## Develop

```sh
cargo run            # listens on 0.0.0.0:8080
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

CI (`.github/workflows/relay.yml`) runs fmt/clippy/test and builds and pushes the multi-arch image to GHCR. Merges to `main` publish `latest`; a tag such as
`relay-v0.1.1` publishes the image tag `v0.1.1`.

## Roadmap (this component)

Metadata minimization is the main open work: **sealed-sender** addressing (so the
relay can't see who is delivering), uniform **padding**, and optional **Tor**
routing to hide client IPs. Tracked as audit items 12–16 in the security model.
This relay is **not audited**; do not treat it as hardened.

## License

Licensed under the **GNU Affero General Public License v3.0 only**
(`AGPL-3.0-only`) — see [LICENSE](LICENSE). The AGPL is deliberate for a network
service: if you run a modified relay, §13 requires you to offer its source to the
users interacting with it over the network.
