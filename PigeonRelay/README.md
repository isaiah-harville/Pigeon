# Pigeon Relay

A **zero-knowledge, federated ciphertext mailbox** — the optional internet path
for Pigeon, for reaching peers who are out of Bluetooth/local range and on a
different network (e.g. cellular).

It is deliberately dumb. It stores and forwards opaque ciphertext blobs
addressed by a recipient's public key. It **cannot read messages**, holds no
keys, keeps no accounts, and logs no addresses or content. Confidentiality,
authentication, integrity, forward secrecy, and the safety-number trust check
are all enforced end-to-end by Pigeon clients, *below* this layer. A compromised
relay yields metadata (who connects, when) and the ability to drop/delay
ciphertext — never plaintext or a forged session.

See [`../docs/SECURITY_MODEL.md`](../docs/SECURITY_MODEL.md) §6.1 for the full
threat model and why remote delivery cannot be serverless.

## Run it

```sh
docker run -p 8080:8080 ghcr.io/<owner>/pigeon-relay:latest
```

That's the whole deployment. The image is multi-arch (amd64/arm64), distroless,
non-root, and stateless — point your homelab Kubernetes / Compose / VPS at it,
terminate TLS at your ingress (clients use `wss://`), and you have a relay.

### Configuration (environment)

| Variable                  | Default        | Meaning                                  |
| ------------------------- | -------------- | ---------------------------------------- |
| `PIGEON_RELAY_ADDR`       | `0.0.0.0:8080` | Listen address.                          |
| `PIGEON_RELAY_TTL_SECS`   | `604800` (7d)  | How long an undelivered envelope is kept.|
| `PIGEON_RELAY_MAX_QUEUE`  | `1000`         | Max envelopes retained per mailbox.      |

Storage is **in-memory and ephemeral** by design — a relay is a transient
rendezvous, not durable storage. Run more than one for redundancy (see
Federation).

## Federation

Relays are independent and **never talk to each other** — federation needs no
server-to-server protocol. A user advertises the relay URL(s) they can be
reached at (carried in their contact bundle / QR). To reach a peer, a sender
deposits ciphertext on *that peer's* advertised relays; the peer reads its own
mailbox from the same relays. Anyone can run one; users choose which to trust. No central party.

## Protocol

WebSocket at `GET /ws`, JSON frames. Addresses are hex Ed25519 public keys;
blobs are base64 ciphertext the relay never decodes.

Health: `GET /healthz` → `ok`.

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

The challenge–response means the relay only ever learns *public* keys (which are
the addresses anyway), and only the holder of a mailbox's private key can drain
it. Delivery is at-least-once; Pigeon clients deduplicate at the mesh layer.

## Develop

```sh
cargo run            # listens on 0.0.0.0:8080
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

CI (`.github/workflows/relay.yml`) runs fmt/clippy/test and builds & pushes the
multi-arch image to GHCR on pushes to `main` (paths under `PigeonRelay/`) and on
`relay-v*` tags.

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
