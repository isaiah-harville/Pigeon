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
  tunnel, or any Kubernetes cluster. The relay is tiny and stateless.
- Docker (or any OCI runtime).
- A domain name and TLS. Pigeon clients connect over `wss://`, so you need a
  certificate; terminate TLS at a reverse proxy in front of the relay.

The relay holds queued envelopes **in memory only**, by design — a relay is a
transient rendezvous point, not durable storage. It needs no database and no
persistent volume. Restarting drops undelivered envelopes; senders retry.

## 1. Run the container

```sh
docker run -d --name pigeon-relay \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
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
    environment:
      PIGEON_RELAY_TTL_SECS: "604800"
      PIGEON_RELAY_MAX_QUEUE: "1000"
```

### Configuration

| Variable                 | Default        | Meaning                                   |
| ------------------------ | -------------- | ----------------------------------------- |
| `PIGEON_RELAY_ADDR`      | `0.0.0.0:8080` | Listen address inside the container.      |
| `PIGEON_RELAY_TTL_SECS`  | `604800` (7d)  | How long an undelivered envelope is kept. |
| `PIGEON_RELAY_MAX_QUEUE` | `1000`         | Max envelopes retained per mailbox.       |

Lower the TTL and queue size if you want a relay that forgets faster; both trade
deliverability for retention.

## 2. Terminate TLS

Clients require `wss://`, so the proxy must upgrade WebSocket connections and
serve a valid certificate. Point it at `http://127.0.0.1:8080`.

### Caddy

Caddy gets you a certificate automatically and proxies WebSockets with no extra
configuration:

```caddy
relay.example.com {
    reverse_proxy 127.0.0.1:8080
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

- **Sizing.** Memory scales with queued, undelivered envelopes
  (`MAX_QUEUE` × mailbox count). A small VPS handles a community.
- **Backups.** None. State is intentionally ephemeral.
- **Updates.** `docker pull` the `latest` tag and recreate the container.
  Versioned tags (e.g. `1.2.3`) are published for pinning.
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
