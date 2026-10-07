# Host a Relay

A Pigeon relay is a **blind ciphertext mailbox**. It stores and forwards opaque
blobs addressed by a recipient's public key so people can reach each other when
they are out of Bluetooth/local range and on different networks.

A relay **cannot read your messages**. It holds no keys, keeps no accounts, and
never sees plaintext — confidentiality, authentication, forward secrecy, and the
safety-number trust check are all enforced end-to-end by Pigeon clients, below
this layer. Running one is how you avoid depending on someone else's server:
relays are federated, and anyone can run their own.

!!! warning "Not audited"
    Pigeon is pre-release and has not been independently audited. A relay
    operator can see connection metadata (which keys connect, when, and roughly
    how much traffic) and can drop or delay ciphertext — never read it.

## What you need

- A machine reachable from the internet — a $5 VPS, a homelab box behind a
  tunnel, or any Kubernetes cluster.
- Docker (or any OCI runtime).
- A domain name and TLS. Pigeon clients connect over `wss://`, so you need a
  certificate; terminate TLS at a reverse proxy in front of the relay.

Pairwise envelopes remain **in memory only** and senders retry after a restart.
Group registrations, opaque group ciphertext, capability state, dissolution
tombstones, and coordinator receipt chains are committed to SQLite before they
are acknowledged. Mount the relay state directory on persistent storage and keep
the stable coordinator signing seed in a separate secret manager.

## 1. Run the container

```sh
openssl rand -hex 32 # store this in your secret manager
docker run -d --name pigeon-relay \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v pigeon-relay-state:/var/lib/pigeon-relay \
  -e PIGEON_COORDINATOR_SIGNING_SEED_HEX='<stored 64-character hex seed>' \
  -e PIGEON_TRUSTED_PROXY_IP='<proxy IP seen by the container>' \
  ghcr.io/isaiah-harville/pigeon/relay:latest
```

That is the whole deployment. The image is multi-arch (amd64/arm64),
distroless, and runs as a non-root user with no shell.

Binding to `127.0.0.1` keeps the plain-HTTP port private; your reverse proxy is
the only thing that talks to it. Check it is alive:

```sh
curl http://127.0.0.1:8080/healthz   # -> ok
```

### Docker Compose

```yaml
services:
  relay:
    image: ghcr.io/isaiah-harville/pigeon/relay:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - pigeon-relay-state:/var/lib/pigeon-relay
    environment:
      PIGEON_RELAY_TTL_SECS: "2592000"
      PIGEON_RELAY_MAX_QUEUE: "1000"
      PIGEON_COORDINATOR_SIGNING_SEED_HEX: "${PIGEON_COORDINATOR_SIGNING_SEED_HEX}"

volumes:
  pigeon-relay-state:
```

### Configuration

| Variable                       | Default         | Meaning                                    |
| ------------------------------ | --------------- | ------------------------------------------ |
| `PIGEON_RELAY_ADDR`            | `0.0.0.0:8080`  | Listen address inside the container.       |
| `PIGEON_RELAY_STATE_DIR`       | `/var/lib/pigeon-relay` | Durable group/coordinator SQLite directory. |
| `PIGEON_RELAY_TTL_SECS`        | `2592000` (30d) | How long an undelivered envelope is kept.  |
| `PIGEON_RELAY_MAX_QUEUE`       | `1000`          | Max envelopes retained per mailbox.        |
| `PIGEON_RELAY_MAX_MAILBOXES`   | `10000`         | Max mailboxes held at once.                |
| `PIGEON_RELAY_MAX_TOTAL_BYTES` | `536870912`     | Hard ceiling on total stored ciphertext.   |
| `PIGEON_GROUP_TTL_SECS` | `2592000` (30d) | Group ciphertext and dissolved-group read grace period. |
| `PIGEON_GROUP_LEASE_SECS` | `2592000` (30d) | Idle period before a group with no retained ciphertext releases its active slot. |
| `PIGEON_GROUP_ADMISSION_DIFFICULTY_BITS` | `18` | Proof-of-work difficulty for anonymous new registrations (1–28 bits). Benchmark on supported phones before release. |
| `PIGEON_GROUP_MAX_GROUPS` | `10000` | Maximum active groups; inactive authorization remains on disk. |
| `PIGEON_GROUP_MAX_CAPABILITIES` | `128` | Maximum member capabilities per group. |
| `PIGEON_GROUP_MAX_ENTRY_BYTES` | `1048576` | Maximum opaque group entry (at most 1 MiB). |
| `PIGEON_GROUP_MAX_ENTRIES` | `10000` | Maximum retained entries per group. |
| `PIGEON_GROUP_MAX_TOTAL_BYTES` | `536870912` | Hard ceiling on group ciphertext. |
| `PIGEON_GROUP_MAX_FETCH_BYTES` | `4194304` | Maximum group fetch response. |
| `PIGEON_COORDINATOR_MAX_PER_EPOCH` | `256` | Candidate attempts retained per epoch. |
| `PIGEON_COORDINATOR_MAX_PER_CAPABILITY_PER_EPOCH` | `8` | Candidate attempts retained per member capability and epoch. |
| `PIGEON_COORDINATOR_MAX_LOGS` | `10000` | Maximum logs with retained candidates; receipt heads remain durable. |
| `PIGEON_COORDINATOR_MAX_CANDIDATES_PER_LOG` | `10000` | Maximum retained candidates per group log. |
| `PIGEON_COORDINATOR_MAX_CANDIDATE_BYTES` | `1048576` | Maximum opaque MLS candidate (at most 1 MiB). |
| `PIGEON_COORDINATOR_MAX_TOTAL_BYTES` | `268435456` | Hard ceiling on coordinator candidates. |
| `PIGEON_COORDINATOR_MAX_FETCH_BYTES` | `4194304` | Maximum coordinator fetch response. |
| `PIGEON_COORDINATOR_TTL_SECS` | `2592000` (30d) | Coordinator candidate lifetime. |
| `PIGEON_COORDINATOR_SIGNING_SEED_HEX` | required | Stable 32-byte Ed25519 seed, hex encoded. |

Lower ciphertext TTLs and queue sizes trade deliverability for retention. An
inactive lease releases an active slot but keeps authorization generation,
capabilities, cursors, sequence, and coordinator receipt history. Current members
can reactivate when capacity is available. Budget disk for that retained state;
the active-group limit is not a disk limit. Keep group and coordinator TTLs aligned
for terminal MLS commit delivery. Never
rotate the coordinator seed for an existing deployment: clients authenticate
that key as part of group policy, so rotation requires explicit in-app recovery.

`PIGEON_RELAY_MAX_MAILBOXES` and `PIGEON_RELAY_MAX_TOTAL_BYTES` are the pairwise
capacity ceiling. They matter because **anyone can deposit** — a sender is
anonymous to the relay, so there is no account to rate limit. Past the mailbox
limit, a deposit addressed to a *new* mailbox is refused and existing mailboxes
keep working. Past the byte limit, each deposit evicts the oldest envelope from
whichever mailbox is holding the most, so a flooding address pays for its own
pressure rather than evicting everyone else's mail.

## 2. Terminate TLS

Clients require `wss://`, so the proxy must upgrade WebSocket connections and
serve a valid certificate. Point it at `http://127.0.0.1:8080`.

### Caddy

Caddy gets you a certificate automatically and proxies WebSockets:

```caddy
relay.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Real-IP {remote_host}
    }
}
```

### nginx

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # Connections are long-lived; don't let the proxy cut idle sockets.
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

The last two lines matter: a Pigeon client holds an open WebSocket to receive
messages, and a short proxy timeout shows up as a relay that keeps dropping.

## 3. Verify it

From anywhere:

```sh
curl https://relay.example.com/healthz   # -> ok
```

Then check the WebSocket endpoint upgrades (`websocat` or any WS client):

```sh
websocat wss://relay.example.com/ws
```

A connection that opens and stays open is a working relay. Depositing requires
no authentication (senders are anonymous to the relay); reading a mailbox
requires proving ownership of its key by signing a challenge, so nobody can
drain a mailbox they don't hold the private key for.

## 4. Add it in the app

In Pigeon: **Menu → Internet relays**, type your endpoint into the field at the
bottom of the relay list, and tap **Add**.

```
wss://relay.example.com/ws
```

Note the `/ws` path — the endpoint is the WebSocket route, not the bare host.
Your enabled relays are advertised in your contact card (QR code), which is how
contacts learn where to deposit ciphertext for you. Contacts you added *before*
adding the relay won't know about it until they re-scan your code.

You can keep several relays enabled at once for redundancy, and disable the
recommended one if you only want your own. Disabling every relay makes Pigeon
fully serverless again — peers are then reachable only over Bluetooth and local
Wi-Fi.

## Federation

Relays never talk to each other, so there is no server-to-server protocol to
configure and no network to join. Users advertise the relay URL(s) they can be
reached at; a sender deposits on *the recipient's* relays. Anyone can run one,
and users choose which to trust. That is the whole federation story.

This also means hosting a relay for a few friends is a complete, useful thing to
do — you do not need to serve the world for it to work.

## Operating notes

- **Connection limits.** The relay caps all WebSockets globally and limits each
  client IP to 32 sockets and 12 invite publishes per minute. Set
  `PIGEON_TRUSTED_PROXY_IP` to the exact TCP peer address the relay sees for
  your proxy; only that peer's `X-Real-IP` header is trusted. Without this
  setting, all proxied clients share one per-IP quota. Make the relay port
  private and have the proxy overwrite `X-Real-IP` with its observed client IP.
- **Sizing.** Memory is capped by `MAX_TOTAL_BYTES` (512 MiB by default) plus a
  small per-connection overhead. A small VPS handles a community.
- **Backups.** Back up `/var/lib/pigeon-relay` and the coordinator seed as one
  recovery set. Stop the relay for a filesystem copy, or use a SQLite-aware
  snapshot; copying only the main database files while WAL files are active can
  omit committed state. Pairwise queues are intentionally excluded.
- **Updates.** `docker pull` the `latest` tag and recreate the container.
  Versioned tags (for example `v1.2.3`) are published for pinning.
- **Logs.** The relay does not log addresses or content. Keep it that way — do
  not add access logging at the proxy that records mailbox keys.
- **Push notifications** are not available to self-hosted relays. An APNs push
  can only be signed by the holder of the app's Apple key, so wake-up pushes
  come from the official relay only; a self-hosted relay still delivers whenever
  Pigeon is running or foregrounded.

## License

`pigeon-relay` is licensed **AGPL-3.0-only**. Running the stock image is
unrestricted. If you run a *modified* relay, §13 of the AGPL requires you to
offer its source to the users interacting with it over the network.

See the [Security Model](SECURITY_MODEL.md) §6.1 for the metadata trade-off of
remote delivery, and the
[pigeon-relay reference](https://github.com/isaiah-harville/Pigeon/tree/main/pigeon-relay)
for the wire protocol.
