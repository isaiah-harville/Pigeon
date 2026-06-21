# How Pigeon Works

This is a thorough tour of how Pigeon keeps your messages private.

For the precise, audit-oriented treatment, read the
[Security Model](SECURITY_MODEL.md).

---

## The one big idea: end-to-end encryption

Put a message in a steel box, lock it, hand it to a courier. The courier carries
it across town to your friend, who has the only key that opens it. The courier
never sees inside — and it doesn't matter if the courier is nosy, hacked, or
secretly hostile.

That's **end-to-end encryption (E2EE)**: a message is locked on *your* device and
unlocked only on your friend's. Everything in between is an untrusted courier
moving a box it can't open. Pigeon has several couriers — Bluetooth, Wi-Fi,
internet relays — and the crucial design choice is that **the lock is identical
regardless of courier.** The rest of this document explains (1) what the lock is
made of and (2) how two phones agree on a key that *only they* know, over a
channel that someone may be watching.

---

## Building block 1 — Two kinds of keys

### Symmetric keys (one shared secret)

The simplest encryption uses **one** secret key to both lock and unlock, like a
physical key that works in both directions. This is **symmetric** encryption.
Pigeon's symmetric workhorse is **AES-256**, the Advanced Encryption Standard at
its 256-bit key size ([FIPS 197][fips197]) — the most widely deployed block
cipher in the world.

But a cipher alone only hides content; it doesn't stop tampering. Every secret
Pigeon stores or sends is therefore **authenticated** too:

- **Confidentiality:** without the key, the ciphertext is indistinguishable from
  random noise.
- **Integrity/authenticity:** if anyone flips even one bit, decryption *fails
  loudly* rather than returning garbage — you cannot tamper undetected.

Two standard constructions provide that second guarantee. Messages between peers
use **AES-256-CBC encrypt-then-MAC**: encrypt with AES, then stamp the ciphertext
with **HMAC-SHA256** (a keyed hash) so any change is detected — the classic
authenticated-encryption recipe ([Bellare & Namprempre 2000][etm]). At-rest
storage on the device uses **AES-256-GCM**, a single-pass **AEAD** mode —
*Authenticated Encryption with Associated Data* ([Rogaway 2002][aead]) — that
locks content and authenticity together in one operation.

The catch: symmetric encryption needs both parties to already share the secret
key. Which raises the central question of all messaging crypto — *how do two
phones agree on a shared secret without ever transmitting it?* That needs the
second kind of key.

### Asymmetric keys (a public/private pair)

In **public-key** (asymmetric) cryptography, each device has a **key pair**: a
**public key** safe to hand to anyone, and a **private key** that never leaves the
device. They're linked by a mathematical "trapdoor" — easy to compute one way,
infeasible to reverse. This idea was introduced by Diffie and Hellman in 1976
([New Directions in Cryptography][dh76]).

Pigeon's pairs live on **Curve25519**, an elliptic curve designed by Daniel
Bernstein for speed and to avoid the subtle implementation pitfalls of older
curves ([Bernstein 2006][curve25519]). It's used in two distinct roles, with two
separate keys:

- **X25519** — for *key agreement* (Diffie–Hellman on Curve25519),
  standardized in [RFC 7748][rfc7748]. This is the key the **Olm** session
  protocol (below) uses as a device's **Curve25519 identity key** and for every
  ratchet step.
- **Ed25519** — for *digital signatures* (the EdDSA scheme), standardized in
  [RFC 8032][rfc8032] (paper: [Bernstein et al. 2012][ed25519]). This is Pigeon's
  long-term **identity key** — the root of who you are.

> **Why two keys, not one?** Signing and key-agreement are different jobs with
> different math, and good hygiene keeps them on separate keys. Pigeon's Ed25519
> identity key *signs* (proves "this came from me") while the Curve25519 key
> *agrees on secrets* (used to derive shared keys). Apple's Secure Enclave can't
> hold these — it only supports the NIST P-256 curve, not Curve25519 — which is
> the deliberate trade-off noted in the [Security Model](SECURITY_MODEL.md) §4.

The two operations public keys enable:

1. **Signatures.** You stamp data with your **private** Ed25519 key; anyone checks
   the stamp with your **public** key and learns it genuinely came from you and
   wasn't altered. Forging a stamp without the private key is infeasible.
2. **Key agreement (Diffie–Hellman).** Two parties combine *their own private key*
   with *the other's public key* and independently arrive at the **same** shared
   secret — without that secret ever crossing the wire (mechanism below).

On every diagram in this doc, the red **"Keychain · private keys"** badge under
each phone names these keys and their jobs: *Ed25519 identity → sign*, *Curve25519
key → ECDH*, *ratchet keys → decrypt*. Red is a running reminder: **this material
never leaves the device.**

### Hashes and key derivation

Two more tools appear throughout:

- A **cryptographic hash** turns any input into a fixed-size fingerprint that's
  infeasible to reverse or to collide. Pigeon uses the SHA-2 family
  ([SHA-256/SHA-512][fips180]). Your device's **fingerprint/address** is the
  SHA-256 hash of your public identity key.
- A **KDF** (key derivation function) stretches and mixes secret material into
  fresh keys with clean separation between uses. Pigeon uses **HKDF**
  ([RFC 5869][rfc5869]) and per-message hashing, which is what lets the ratchet
  (below) mint a new key for every message.

---

## Building block 2 — Diffie–Hellman, the "agree on a secret in public" trick

How can two phones end up with the same secret when an eavesdropper sees
everything they exchange?

> **The paint intuition.** You and a friend publicly agree on a common paint
> color. Each secretly picks a private color and mixes it into the common one,
> then you swap the *mixtures* in the open. Each of you mixes your own secret into
> what you received. You both reach the *same* final blend — yet a watcher who saw
> only the common color and the two mixtures can't separate them back out.

Digitally, "mixing" is multiplying points on Curve25519, and "un-mixing" is the
**elliptic-curve discrete logarithm problem**, believed infeasible at this key
size. Concretely (**X25519**, [RFC 7748][rfc7748]): Alice has private `a`/public
`A`, Bob has `b`/`B`. Alice computes `a·B`, Bob computes `b·A`, and the curve math
makes both equal `a·b·G` — the shared secret. The private keys `a` and `b` never
leave their devices; only the public points `A` and `B` are sent. This single
operation — "**ECDH**" on the badges — is the foundation of everything that
follows.

---

## Step 1 — Becoming contacts, in person

![Identity and trust: in-person QR setup](diagrams/pigeon_01_identity.png)

*Two phones generate keys, exchange public ContactCards by QR, and verify a safety
number — no server involved.*

Pigeon has no accounts, phone numbers, or central directory. **You are your key
pair**, addressed by your fingerprint. Trust is established the hard-to-fool way:
**in person.**

1. **Each phone generates its keys** (an Ed25519 identity key, plus an Olm
   account holding a Curve25519 identity key and a pool of prekeys) on first
   launch and stores the private halves in the **Keychain** (details in
   [Where the secrets live](#where-the-secrets-live)).
2. **You show each other a QR code** encoding a **ContactCard**: your *public*
   Ed25519 identity key, your *public* Olm Curve25519 key, a signed *prekey*
   bundle (so people can message you while you're offline — see Step 2), a display
   name, and any relay addresses. It's all public — safe even if photographed by a
   stranger.
3. **Each phone verifies the card is internally consistent.** The card carries an
   Ed25519 signature, made by the identity key, over the Curve25519 key. Checking
   it proves the two keys belong together — an attacker can't staple their own
   Curve25519 key onto your identity.
4. **You compare a safety number.** Pigeon derives one 60-digit number from *both*
   public identity keys — identical on both phones — and you confirm they match
   (read aloud or scanned). This mirrors Signal's "safety number" design
   ([Signal][safetynum]); Pigeon computes it by iterated SHA-512 hashing over the
   two keys sorted into a fixed order, so the result is the same on both devices
   and grinding a collision is expensive.

Why step 4 is the linchpin:

> **The man-in-the-middle (MITM) attack it stops.** Picture an adversary who can
> intercept and relay your traffic, handing each of you *their* key while
> impersonating the other. They could then sit invisibly between you and read
> everything. The defense isn't math alone — it's *human verification*: the safety
> number is computed from the **real** keys each phone holds, so an injected key
> changes it. Comparing it while looking at your actual friend is what anchors the
> cryptography to a real person. (Authenticated key exchange formalizes exactly
> this guarantee; see the Signal protocol analysis, [Cohn-Gordon et al.
> 2017][signalanalysis].)

After this, your friend is a **verified contact**, permanently.

---

## Step 2 — Opening a channel: an Olm session

Now both phones must derive a shared secret *and* each confirm **who** the other
is. Pigeon does this with **Olm**, the session protocol from the Matrix project,
as implemented by the audited [`vodozemac`][vodozemac] Rust crate. Pigeon does
**not** re-implement the ratchet or the key math — it drives Olm's account and
session API and adds exactly one thing of its own: the identity check at the end.

Olm is **asynchronous**: the sender does **not** need the recipient online. That
matters enormously for a mesh — peers are out of range all the time. It works
through **prekeys**: keys the recipient publishes *ahead of time* in its
ContactCard so anyone can start a session with them later.

- Each device's Olm account holds a long-term **Curve25519 identity key**, a
  rotating **signed prekey**, and a pool of **one-time prekeys** — all public,
  all carried in the QR card from Step 1, and each one signed by the Ed25519
  identity key.
- To open a session, the sender generates a fresh **ephemeral** key and performs
  several Diffie–Hellman operations against the recipient's published keys —
  ephemeral-with-identity, ephemeral-with-signed-prekey, ephemeral-with-one-time
  — and folds the results together (via **HKDF-SHA256**) into a shared root
  secret. This is the same multi-DH idea pioneered by Signal's X3DH
  ([Marlinspike & Perrin][x3dh]); Olm uses it as its session-setup step.
- That first encrypted message carries the sender's ephemeral and one-time-key
  choices, so the recipient — whenever it next comes online — can run the
  matching DHs and arrive at the *same* root secret. The one-time prekey is then
  **deleted**, so it can never be reused.

The outcome is the same as any good handshake: **a shared secret** no
eavesdropper can reconstruct (they only saw public points), with **forward
secrecy** from the ephemeral and one-time keys, plus each side learning the
other's Curve25519 identity key.

Then Pigeon adds its one project-specific check — the **binding check**: it
confirms the Curve25519 identity key in the session **equals the one in the
ContactCard you verified in person**, which the Ed25519 identity signed (Security
Model §5.2). This staples the encrypted channel to the specific human you checked,
so "encrypted" also means "encrypted *to the right person*."

---

## Step 3 — Every message its own key: the Double Ratchet

The handshake yields a shared secret, but Pigeon doesn't just reuse it forever. It
runs the **Double Ratchet** ([Perrin & Marlinspike][doubleratchet]), the algorithm
behind Signal, WhatsApp, and others.

"Ratchet" = a mechanism that only moves forward and can't be wound back. There are
two interlocking ratchets:

- **The symmetric-key ratchet.** For each message, a per-message **message key** is
  derived from a "chain key" via a one-way KDF, and the chain key is advanced. The
  old message key is *deleted immediately after use.* Because the KDF is one-way,
  knowing a current key tells you nothing about previous ones.
- **The Diffie–Hellman ratchet.** Periodically (as each side replies), the parties
  attach a fresh ephemeral public key and perform a new DH, injecting brand-new
  randomness into the key schedule. This is what lets the conversation *recover*
  after a compromise.

Together they provide two properties worth naming:

- **Forward secrecy** — past messages stay confidential even if the device is
  later compromised, because their keys were already destroyed. (The general
  principle dates to the authenticated-key-exchange literature; see
  [Cohn-Gordon et al. 2017][signalanalysis].)
- **Post-compromise security** ("self-healing") — if an attacker transiently
  learns a key, the next DH-ratchet step locks them back out
  ([Cohn-Gordon, Cremers & Garratt 2016][pcs]).

On the diagrams this is the *"ratchet message key → decrypt"* step — and it's why
stealing one key can never unlock your whole history.

> **You can message someone who's offline.** Because the Olm session in Step 2 is
> built from the recipient's *published* prekeys, you never need both phones awake
> at once. Your first message ships as a self-contained "pre-key message" — it
> carries everything the recipient needs to derive the shared secret whenever they
> next come online, over Bluetooth or via a relay. From their reply onward, the
> Double Ratchet above takes over.

---

## Step 4 — The couriers (transports)

Everything above produces **ciphertext** — the locked box. It then travels over
whatever connection is available; multiple transports can run at once, and none
can read the box.

### Bluetooth LE mesh — when you're nearby

![Bluetooth LE mesh](diagrams/pigeon_02_bluetooth.png)

*An Olm session opened from published prekeys and an encrypted message over
Bluetooth — no server.*

In range, two phones talk directly with no internet or account. If a peer is just
out of range, nearby Pigeon devices forward the still-locked box onward — a
**mesh**. Each hop sees only ciphertext (plus a small amount of routing
metadata). This works on a plane, at a protest, during an outage — anywhere the
internet is absent or untrusted.

### Local Wi-Fi — same lock, more bandwidth *(planned)*

![Local Wi-Fi (planned)](diagrams/pigeon_03_wifi.png)

*Identical end-to-end crypto to Bluetooth; only the link layer changes.*

A planned transport for devices on the same network. The diagram is deliberately
the *same* as Bluetooth apart from the courier — the whole point of Pigeon's
pluggable transport design. The LAN carries only ciphertext.

### Relay — when you're far apart *(zero-knowledge)*

![Federated relay](diagrams/pigeon_04_relay.png)

*A blind mailbox: it stores opaque ciphertext addressed by public key and never
sees content or private keys.*

Two phones on different networks (e.g. both on cellular) usually can't connect
directly: behind NAT, a phone can dial out but not be dialed in. They need a
mutually reachable rendezvous on the internet. Pigeon's is a **relay** — a
deliberately dumb, **zero-knowledge** mailbox. What makes trusting it unnecessary:

- **Your mailbox address is just your public key.** To *read* it you prove
  ownership via **challenge–response**: the relay sends a random nonce, you sign it
  with your Ed25519 **private** key (which never leaves the phone), and the relay
  verifies the signature against your public key. The relay only ever learns
  *public* keys.
- Anyone can **drop off** a locked box for your mailbox; the relay **stores and
  forwards** it (up to 7 days) until you fetch it, then deletes it once your phone
  acknowledges receipt.
- The relay **never** sees plaintext, holds no keys, and cannot forge a message
  (integrity/authenticity are guaranteed end-to-end by the Olm session's message
  authentication). See its gray badge: *"Holds no keys."*

What a relay *can* observe is **metadata** — that some ciphertext was deposited for
some public key, its size, and timing. That's not nothing, which is why relays are
**opt-in** and **federated**: anyone can run one, you choose which, and you can
self-host. Reducing this metadata further (padding, sealed-sender addressing,
optional Tor) is on the [Roadmap](ROADMAP.md).

---

## Step 5 — Notifications without leaking

A locked phone is the hard case. To *decrypt*, Pigeon must open its on-device
message store, which is sealed behind Face ID / your passcode — and you can't do
Face ID while the phone is asleep in your pocket. The design threads this needle.

### Today: notify now, decrypt at unlock

![Notifications while locked](diagrams/pigeon_05_notifications.png)

*A locked phone receives ciphertext, shows a content-free alert, and decrypts only
after you unlock.*

1. The phone can still **receive**: its identity key is readable in the background
   after the first unlock since boot (Apple's `AfterFirstUnlock` data-protection
   class — [Apple Platform Security][appsec]). The message store stays sealed (the
   badge reads *"message vault → locked"*).
2. It therefore **can't decrypt**, so it holds the locked box in memory and posts a
   **content-free** alert — just "New message," no sender, no preview. It also
   does *not* yet acknowledge the relay, so the box is safely retained server-side
   until you actually read it.
3. On unlock, the store opens, the ratchet decrypts the buffered box, and the
   message appears.

> Even the notification reveals nothing about who messaged you or what they said —
> a deliberate lock-screen privacy choice.

### Planned: push wake-ups via APNs

![Notifications with APNs push (planned)](diagrams/pigeon_06_notifications_apns.png)

*A content-free push wakes the phone; the message itself never travels through
Apple.*

iOS eventually suspends a backgrounded app, so for reliable delivery hours later,
Pigeon plans to use Apple Push Notification service (**APNs**,
[Apple developer docs][apns]) purely as a doorbell:

- You **opt in**; your phone registers an opaque APNs token with Pigeon's
  **official** relay. (Only the app's publisher can push to the app, so this part
  can't be federated — it lives on the official relay only; see the
  [Roadmap](ROADMAP.md) and issue tracker.)
- When a box arrives, the relay asks APNs to send a **content-free** wake-up. Your
  phone wakes, fetches the locked box, and — as before — only decrypts after you
  unlock.
- Apple and the gateway see a **token, timing, and a blank wake** — never your
  message (APNs's gray badge: *"never content"*).

This trades a little "someone pinged this device" metadata for reliable
notifications, strictly opt-in. Confidentiality remains end-to-end.

---

## What an attacker can and can't do

**A snoop on the wire, a malicious or hacked relay, or your phone company *cannot*:**

- read your messages — they only ever hold authenticated ciphertext (AES-256 with
  HMAC-SHA256, [Bellare & Namprempre 2000][etm]);
- impersonate a contact you verified in person — the safety number + binding check
  expose a substituted key;
- recover past messages from a key stolen later — the ratchet already deleted it
  (forward secrecy, [Cohn-Gordon et al. 2017][signalanalysis]).

**They *can* still learn some things — and Pigeon says so plainly:**

- A **relay** sees metadata (that ciphertext moved for some public key, its size,
  timing). Opt-in; mitigations planned.
- Over **Bluetooth**, nearby devices can detect a Pigeon device's presence.
- If your phone is taken while **unlocked**, your messages are exposed — no app can
  protect an unlocked device in someone else's hand.

And the standing caveat: **Pigeon is pre-audit.** The building blocks (CryptoKit,
Olm via the audited `vodozemac`, the Double Ratchet) are well-studied, but
Pigeon's *assembly* of them — and its glue code — has not yet had an independent
security audit and must not be treated as proven-secure. See the
[Security Model](SECURITY_MODEL.md) and [Roadmap](ROADMAP.md).

---

## Where the secrets live

- **Private keys** (the Ed25519 identity key and the Olm account: its Curve25519
  identity key and prekeys) are stored in the iPhone **Keychain**, marked
  *this-device-only*: never synced to iCloud, never in backups, never moved to
  another device. Their *lock-state* accessibility is
  `WhenUnlocked` by default, or `AfterFirstUnlock` if you enable background
  delivery — both are Apple data-protection classes ([Apple Platform
  Security][appsec]).
- The **message store** is encrypted with a key sealed behind **Face ID /
  passcode**, so your history stays locked until you authenticate even if the
  phone is in hand.
- **No key is ever sent to any server.** Servers handle locked boxes only.

That's the whole system: verify a friend once, in person; agree on a secret no one
else can compute, even when they're offline (an Olm session from published
prekeys); authenticate who you're talking to (the identity binding check); give
every message its own disposable key (the Double Ratchet); and let any courier
carry the locked box, because none of them hold the key to open it.

---

## References

Standards and specifications:

- <a id="references"></a>**RFC 7748** — *Elliptic Curves for Security* (X25519 key
  agreement). <https://www.rfc-editor.org/rfc/rfc7748>
- **RFC 8032** — *Edwards-Curve Digital Signature Algorithm (EdDSA)* (Ed25519).
  <https://www.rfc-editor.org/rfc/rfc8032>
- **M. Bellare & C. Namprempre**, *Authenticated Encryption: Relations among
  Notions* (encrypt-then-MAC), ASIACRYPT 2000. <https://eprint.iacr.org/2000/025>
- **FIPS 197** — *Advanced Encryption Standard (AES)*.
  <https://csrc.nist.gov/pubs/fips/197/final>
- **NIST SP 800-38D** — *Galois/Counter Mode (GCM) and GMAC* (the at-rest AEAD).
  <https://csrc.nist.gov/pubs/sp/800/38/d/final>
- **RFC 5869** — *HMAC-based Key Derivation Function (HKDF)*.
  <https://www.rfc-editor.org/rfc/rfc5869>
- **FIPS 180-4** — *Secure Hash Standard* (SHA-256 / SHA-512).
  <https://csrc.nist.gov/pubs/fips/180-4/upd1/final>
- **Olm** — *Olm: A Cryptographic Ratchet* (the session protocol Pigeon uses).
  <https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md>
- **vodozemac** — audited Rust implementation of Olm/Megolm.
  <https://github.com/matrix-org/vodozemac>
- **The Double Ratchet Algorithm** — Trevor Perrin & Moxie Marlinspike, 2016.
  <https://signal.org/docs/specifications/doubleratchet/>
- **The X3DH Key Agreement Protocol** — Marlinspike & Perrin, 2016.
  <https://signal.org/docs/specifications/x3dh/>
- **Signal safety numbers** — Signal Support.
  <https://support.signal.org/hc/en-us/articles/360007060632>
- **Apple Platform Security** — Keychain data protection classes & APNs.
  <https://support.apple.com/guide/security/welcome/web>
- **Apple — Apple Push Notification service (APNs)**.
  <https://developer.apple.com/documentation/usernotifications>

Foundational papers:

- **W. Diffie & M. Hellman**, *New Directions in Cryptography*, IEEE Trans.
  Information Theory, 1976. <https://doi.org/10.1109/TIT.1976.1055638>
- **D. J. Bernstein**, *Curve25519: New Diffie-Hellman Speed Records*, PKC 2006.
  <https://cr.yp.to/ecdh.html>
- **D. J. Bernstein, N. Duif, T. Lange, P. Schwabe, B.-Y. Yang**, *High-speed
  high-security signatures* (Ed25519), 2012. <https://ed25519.cr.yp.to/>
- **P. Rogaway**, *Authenticated-Encryption with Associated-Data* (AEAD), CCS 2002.
  <https://web.cs.ucdavis.edu/~rogaway/papers/ad.html>
- **K. Cohn-Gordon, C. Cremers, B. Dowling, L. Garratt, D. Stebila**, *A Formal
  Security Analysis of the Signal Messaging Protocol*, EuroS&P 2017.
  <https://eprint.iacr.org/2016/1013>
- **K. Cohn-Gordon, C. Cremers, L. Garratt**, *On Post-Compromise Security*, IEEE
  CSF 2016. <https://eprint.iacr.org/2016/221>

*The diagrams are generated from
[`docs/diagrams/generate_diagrams.py`](diagrams/generate_diagrams.py) — run
`uv run docs/diagrams/generate_diagrams.py` to regenerate them after a protocol
change.*

[rfc7748]: https://www.rfc-editor.org/rfc/rfc7748
[rfc8032]: https://www.rfc-editor.org/rfc/rfc8032
[rfc5869]: https://www.rfc-editor.org/rfc/rfc5869
[fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
[fips197]: https://csrc.nist.gov/pubs/fips/197/final
[etm]: https://eprint.iacr.org/2000/025
[vodozemac]: https://github.com/matrix-org/vodozemac
[doubleratchet]: https://signal.org/docs/specifications/doubleratchet/
[x3dh]: https://signal.org/docs/specifications/x3dh/
[safetynum]: https://support.signal.org/hc/en-us/articles/360007060632
[appsec]: https://support.apple.com/guide/security/welcome/web
[apns]: https://developer.apple.com/documentation/usernotifications
[dh76]: https://doi.org/10.1109/TIT.1976.1055638
[curve25519]: https://cr.yp.to/ecdh.html
[ed25519]: https://ed25519.cr.yp.to/
[aead]: https://web.cs.ucdavis.edu/~rogaway/papers/ad.html
[signalanalysis]: https://eprint.iacr.org/2016/1013
[pcs]: https://eprint.iacr.org/2016/221
