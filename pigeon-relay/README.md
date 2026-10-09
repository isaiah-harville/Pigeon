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
  -v pigeon-relay-state:/var/lib/pigeon-relay \
  -e PIGEON_COORDINATOR_SIGNING_SEED_HEX="<64-hex-character-secret>" \
  ghcr.io/<owner>/pigeon-relay:latest
```

The image is multi-arch (amd64/arm64), distroless, and non-root. Pairwise queues
are memory-only; the named volume preserves group/coordinator state. Point your
homelab Kubernetes / Compose / VPS at it and terminate TLS at your ingress
(clients use `wss://`). The coordinator seed is required in release builds, must
be generated from a cryptographically secure source, and must remain stable
across restarts. Store it in a secret manager; never put it in an image,
manifest, shell history, or logs.

### Configuration (environment)

| Variable                        | Default          | Meaning                                        |
| ------------------------------- | ---------------- | ---------------------------------------------- |
| `PIGEON_RELAY_ADDR`             | `0.0.0.0:8080`   | Listen address.                                |
| `PIGEON_RELAY_STATE_DIR`        | `/var/lib/pigeon-relay` | Durable group/coordinator/invite SQLite directory. |
| `PIGEON_RELAY_MAX_CONNECTIONS` | `1024` | Maximum concurrent WebSocket connections across both endpoints. |
| `PIGEON_RELAY_TTL_SECS`         | `2592000` (30d)  | How long an undelivered envelope is kept.      |
| `PIGEON_RELAY_MAX_QUEUE`        | `1000`           | Max envelopes retained per mailbox.            |
| `PIGEON_RELAY_MAX_MAILBOXES`    | `10000`          | Max mailboxes held at once.                    |
| `PIGEON_RELAY_MAX_TOTAL_BYTES`  | `536870912`      | Hard ceiling on total stored ciphertext.       |
| `PIGEON_GROUP_TTL_SECS`         | `2592000` (30d)  | Entry and dissolution grace lifetime. |
| `PIGEON_GROUP_LEASE_SECS`       | `2592000` (30d)  | Idle time before a group leaves active capacity; unexpired entries remain durable. |
| `PIGEON_GROUP_ADMISSION_DIFFICULTY_BITS` | `18` | Leading SHA-256 zero bits required to register a new group (1–28). Benchmark on supported phones before release. |
| `PIGEON_GROUP_MAX_GROUPS`       | `10000`          | Maximum active groups; inactive authorization remains on disk. |
| `PIGEON_GROUP_MAX_CAPABILITIES` | `128`            | Maximum capabilities in one group.             |
| `PIGEON_GROUP_MAX_ENTRY_BYTES`  | `1048576`        | Maximum opaque group entry (at most 1 MiB).   |
| `PIGEON_GROUP_MAX_ENTRIES`      | `10000`          | Maximum entries retained per group.            |
| `PIGEON_GROUP_MAX_TOTAL_BYTES`  | `536870912`      | Hard ceiling for all group ciphertext.         |
| `PIGEON_GROUP_MAX_FETCH_BYTES`  | `4194304`        | Maximum group fetch response.                  |
| `PIGEON_INVITE_TTL_SECS` | `604800` (7d) | Retention for opaque invite requests and replies, at most one year. |
| `PIGEON_INVITE_MAX_MAILBOXES` | `10000` | Maximum invite inboxes with retained ciphertext. |
| `PIGEON_INVITE_MAX_ENTRIES` | `128` | Maximum retained envelopes per invite inbox. |
| `PIGEON_INVITE_MAX_ENTRY_BYTES` | `16384` | Maximum invite ciphertext; at most 256 KiB. |
| `PIGEON_INVITE_MAX_TOTAL_BYTES` | `67108864` | Hard ceiling for invite ciphertext. |
| `PIGEON_INVITE_MAX_DEPOSITS_PER_MINUTE` | `120` | Per-inbox and relay-wide deposit limit. |
| `PIGEON_COORDINATOR_MAX_PER_EPOCH` | `256`         | Candidate attempts retained per epoch.         |
| `PIGEON_COORDINATOR_MAX_PER_CAPABILITY_PER_EPOCH` | `8` | Candidate attempts per member capability per epoch; at most `MAX_PER_EPOCH`. |
| `PIGEON_COORDINATOR_MAX_LOGS` | `10000` | Maximum logs with retained candidates; receipt heads remain durable. |
| `PIGEON_COORDINATOR_MAX_CANDIDATES_PER_LOG` | `10000` | Maximum retained candidates per group log. |
| `PIGEON_COORDINATOR_MAX_CANDIDATE_BYTES` | `1048576` | Maximum opaque MLS candidate (at most 1 MiB). |
| `PIGEON_COORDINATOR_MAX_TOTAL_BYTES` | `268435456` | Hard ceiling for coordinator candidates.     |
| `PIGEON_COORDINATOR_MAX_FETCH_BYTES` | `4194304`  | Maximum coordinator fetch response.            |
| `PIGEON_COORDINATOR_TTL_SECS`   | `2592000` (30d)  | Coordinator candidate lifetime.                |
| `PIGEON_COORDINATOR_SIGNING_SEED_HEX` | — (required in release) | Stable 32-byte Ed25519 seed, hex encoded. |

Pairwise deposits are unauthenticated, so `PIGEON_RELAY_MAX_MAILBOXES` and
`PIGEON_RELAY_MAX_TOTAL_BYTES` are their abuse bound. Past
`MAX_MAILBOXES` a deposit to a *new* address is refused (existing mailboxes keep
working); past `MAX_TOTAL_BYTES` each deposit evicts the oldest envelope from
whichever mailbox is holding the most, so a flooding address pays for its own
pressure instead of evicting everyone else's mail.

Pairwise mailboxes are **in-memory and ephemeral** by design; senders retransmit
until acknowledgement. Group registrations, opaque group entries, capability
cursors/tombstones, coordinator receipt chains, and opaque invite envelopes are committed to SQLite under
`PIGEON_RELAY_STATE_DIR` before the relay acknowledges them. Mount that directory
on persistent storage and back it up together with the coordinator seed. Clients
authenticate the coordinator public key, and startup fails if the configured seed
does not match the key bound into the stored receipt logs.

An unused registration expires after one group TTL if it has never stored a
group entry, submitted a coordinator candidate, or changed authorization. Groups that have carried traffic retain
authorization until owner dissolution or operator action. Expired coordinator
candidates stop consuming active-log capacity; their signed sequence and head
remain on disk so later receipts continue the same chain.
Expired registrations leave a compact owner-binding tombstone, so another key
cannot claim the same coordination ID. These tombstones and coordinator heads
remain durable and can grow with sustained registration abuse.

Admission allows at most eight registration attempts per WebSocket connection
and 60 new groups per minute across the relay process. Identical retries for an
existing group do not consume the global budget. The limit keeps bursts from
immediately filling durable storage; an attacker who can sustain valid
registrations and traffic can still occupy capacity.

To reclaim an empty registration at capacity, stop the relay and run
`pigeon-relay reclaim-empty-group <state-dir> <coordination-id-hex>`. The command
refuses a group with queued ciphertext or retained coordinator candidates. It
keeps the coordinator receipt head, if any. Back up both SQLite databases and
the signing seed together before maintenance. Reclaiming an empty but still
used group makes its clients re-register and may interrupt delivery; inspect
the group lifecycle before using this operator command.

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

Pairwise and invite WebSocket traffic uses `GET /ws`; group messaging and coordination use
`GET /group/ws`. Both protocols use bounded JSON frames. Connections share a
global capacity limit and must authenticate within 60 seconds if they remain open.
Addresses, group
coordination IDs, capability IDs, cursors, sizes, timing, and client IPs are
relay-visible metadata. Message and MLS candidate bodies remain opaque.

Health: `GET /healthz` → `ok`.

Every WebSocket must negotiate the relay protocol before any mailbox operation:

```json
{ "type": "hello", "min_protocol_version": 2, "max_protocol_version": 2 }
← { "type": "compatible", "protocol_version": 2 }
```

The relay selects the highest overlapping version. A disjoint range receives an
`incompatible` response containing the relay's minimum and maximum, and the
connection cannot publish, subscribe, authenticate, or acknowledge messages.

Shareable invite inboxes require pairwise protocol version 3. An anonymous sender
uses `invite_publish` with a pseudonymous Ed25519 `recipient`, opaque
`ciphertext`, and optional `request_id`; a `published` receipt follows a durable
SQLite commit. A reader uses `invite_subscribe`, then signs the normal challenge
with that inbox key and sends `auth`. It receives retained and live `envelope`
frames and deletes each only with `ack`. These inboxes have separate TTL, entry,
byte, and deposit limits; the relay cannot read or approve a group join. Invite
inboxes do not accept APNs token registration or trigger push wake-ups, avoiding
a relay-side link from a public invite address to a device token. Join requests
wait until an admin reconnects to the invite inbox.

**Deposit (sender, no auth — sender is anonymous to the relay):**

```json
{ "type": "publish", "recipient": "<hex pubkey>", "ciphertext": "<base64>", "request_id": "<sender nonce>" }
→ { "type": "published", "id": "<id>", "request_id": "<sender nonce>" }
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

Group connections separately negotiate protocol version 7 and authenticate a
group-scoped capability challenge. A canonical registration atomically replaces
the complete capability set, which revokes removed members without exposing the
roster's root identities. The coordinator orders opaque candidates and signs an
append-only receipt chain; clients still validate every MLS commit and policy
transition end to end. The service cannot decrypt, authorize, or forge a group
transition, but it can observe group-level metadata and can delay or deny
progress. Each capability may submit at most
`PIGEON_COORDINATOR_MAX_PER_CAPABILITY_PER_EPOCH` candidates per epoch, so one
member cannot exhaust the epoch's shared candidate budget.

New anonymous registrations receive a 32-byte base64 `registration_challenge`
with a difficulty in bits. The client returns a base64 eight-byte
`admission_solution` on the same signed `register` frame within 60 seconds.
The work input is SHA-256 of the admission domain, challenge nonce, SHA-256 of
the canonical registration transcript, and solution bytes. A relay may reject
registration or reactivation with `error { "message": "capacity" }`; clients
can retry later. A group whose lease ends retains its capability keys,
authorization generation, cursors, and next sequence on disk. A current member
can reactivate it by completing the normal capability challenge. Historical
authorization consumes disk; operators must set a disk budget and maintenance
policy. Proof of work raises the cost of mass registration but does not stop a
well-funded attacker.

When the owner dissolves a group, the owner's controller sends `revoke_group`
after the terminal commit is appended. The relay then installs a draining
tombstone: appends, coordinator submissions, and capability changes fail closed
immediately, while existing readers can still authenticate, fetch the terminal
ciphertext and the signed coordinator log, and advance their cursors. The group
and its entries are deleted one `PIGEON_GROUP_TTL_SECS` after dissolution. A
member offline for longer than that never receives the dissolution commit and
sees only a relay that no longer recognizes the group.

On the official deployment, group readers with a registered push token are woken
for new mailbox entries, new coordinator receipts, and dissolution.

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
