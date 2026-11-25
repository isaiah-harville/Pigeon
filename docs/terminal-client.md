# Terminal Client

`pigeon` is Pigeon for the terminal. It sends and receives end-to-end-encrypted
direct messages over Pigeon relays and talks to the iPhone app as an equal: the
same messaging core (`pigeon-core`, Olm through the audited `vodozemac` crate),
the same contact links, the same safety numbers, and the same relay protocol.

It runs on macOS, Linux, and Windows.

!!! note "What it does not do"
    The terminal client handles **direct messages over relays** only. Bluetooth
    and Wi-Fi mesh delivery, group chats, reactions, and push notifications stay
    on the phone. A terminal identity is its own identity: it is not a second
    device for your phone's account, so it appears to your contacts as a
    separate contact.

## Install

You need a Rust toolchain, version 1.89 or newer
([rustup.rs](https://rustup.rs/)). No system TLS library is required; the client
uses rustls.

```sh
git clone https://github.com/isaiah-harville/Pigeon.git
cd Pigeon
cargo install --locked --path pigeon-cli
```

That installs the `pigeon` binary into `~/.cargo/bin`. To build without
installing, run `cargo build --release -p pigeon-cli`; the binary is then at
`target/release/pigeon`.

Check it works:

```sh
pigeon --version
```

## Create your identity

```sh
pigeon init --name "Ada"
```

`init` creates a fresh identity and asks for a passphrase (at least 8
characters, asked twice). The passphrase seals everything the client stores; it
cannot be recovered, and without it the identity is gone.

By default you receive messages on the default Pigeon relay. To receive on your
own relay instead (see [Host a Relay](host-a-relay.md)), name it, and repeat
`--relay` to receive on more than one:

```sh
pigeon init --name "Ada" --relay wss://relay.example.com/ws
```

## Share your contact link

```sh
pigeon card
```

This prints your contact link, a `https://pigeonwire.app/contact#card=…` URL.
Send it to the person you want to talk to, by any channel. On an iPhone, opening
the link adds you in Pigeon; they can also paste it under **Contacts → Add
Contact → Enter Contact Code**. The link carries
only public information: your name, your public identity and pre-keys, and the
relays you receive on, signed by your identity key. `pigeon card --raw` prints
the bare payload the app encodes in its QR code.

## Add a contact

From someone's contact link (or a QR payload, or a base64 card):

```sh
pigeon add 'https://pigeonwire.app/contact#card=…'
```

Quote the link: it contains `#` and other characters your shell would
otherwise interpret.

To get a link from the iPhone app, open the menu, choose **Show my QR code**,
then **Share Contact Link**.

Adding someone from a link starts a **message request**. Your first message
goes out together with your card, and you can send more once they accept. If
you exchanged links face to face and have each compared the other's safety
number, add with `--mutual` to skip the request step:

```sh
pigeon add --mutual 'https://pigeonwire.app/contact#card=…'
```

When someone adds *you*, their first message arrives as a request:

```sh
pigeon contacts          # requests are listed alongside contacts
pigeon accept bob        # accept the request from Bob
```

Wherever a command takes a contact, you can give the start of their name
(`bo` for Bob) or at least six characters of their identity key, as long as
only one contact matches.

## Chat

Run `pigeon` with no arguments for the interactive client:

```sh
pigeon
```

Open a conversation with `/chat <name>`, then type a line and press Return to
send it. Messages that arrive while you are in the chat print as they come in.

| Command | What it does |
| --- | --- |
| `<text>` | Send to the open conversation. |
| `/chat <name>` | Open a conversation. |
| `/contacts` | List contacts and requests. |
| `/add <link> [--mutual]` | Add a contact from their link. |
| `/accept <name>` | Accept a message request. |
| `/card` | Show your contact link. |
| `/safety [name]` | Show the safety number to compare in person. |
| `/verify <name>` | Mark a contact verified after comparing. |
| `/rename <new name>` | Rename the open contact. |
| `/history` | Reprint the open conversation. |
| `/status` | Show relay connections and how many items await a receipt. |
| `/help` | List these commands. |
| `/quit` | Leave. Queued messages are kept. |

`pigeon chat bob` opens straight into the conversation with Bob.

Your own messages show `✓` once the relay has stored them and `✓✓` once the
recipient's device has confirmed delivery.

### One-off commands

For scripts, or a quick message without the interactive client:

```sh
pigeon send bob "Running late, 10 minutes"   # waits until the relay stores it
pigeon listen                                # print messages as they arrive
pigeon history bob                           # print the conversation
```

`send` waits up to 30 seconds for the relay's receipt. If the relay cannot be
reached, the message stays sealed in your vault and goes out the next time you
run `pigeon`, `pigeon send`, or `pigeon listen`.

## Verify a contact

A contact link proves which key you are talking to, but not who holds it. To be
sure, compare safety numbers with the other person in person or on a call you
trust:

```sh
pigeon safety bob
```

Both of you see the same 60-digit number, in groups of five. In the iPhone app,
open the chat, tap the contact's name or the **…** menu, and choose **Safety
Number**. If the numbers match, record
it:

```sh
pigeon safety bob --verified
```

Verified contacts show `[verified]` in `pigeon contacts`. If the number ever
differs, do not trust the conversation until you know why.

## Relays

```sh
pigeon relays                                         # where you receive
pigeon relays wss://relay.example.com/ws              # replace the list
```

After changing relays, run `pigeon card` and send your contacts the new link:
they deliver to the relays your card lists, so until they have the new card
their messages go to the old relays.

You can always send to a contact, whichever relays you receive on: messages go
to the relays *their* card lists.

## Where your data lives

Everything is stored in `~/.pigeon`. Override it with `--home <dir>` or the
`PIGEON_HOME` environment variable, for example to keep separate identities:

```sh
pigeon --home ~/.pigeon-work init --name "Ada (work)"
PIGEON_HOME=~/.pigeon-work pigeon
```

The directory is created owner-only (`0700`, files `0600`). It holds:

- your identity seed, the messaging core's checkpoint (the Olm account and every
  session's ratchet state), and your contacts and message history, each sealed
  with XChaCha20-Poly1305 under a key derived from your passphrase with Argon2id
  (64 MiB, 3 passes), with the file's purpose bound as associated data;
- a lock file that stops two `pigeon` processes from opening the same vault.

Writes are atomic and flushed to disk, and a message from the relay is
acknowledged only after it has been durably applied, so a crash never loses a
received message.

### Backups

You can copy the directory while no `pigeon` process is running; the copy is as
safe as your passphrase. Restore a backup only to **replace** the original,
never to run alongside it: two copies of one identity would each advance their
own ratchets, and messages would stop decrypting for one of them. Restoring an
older backup also rewinds the ratchets, so some messages that arrived after the
backup may fail to open.

## Scripting

`PIGEON_PASSPHRASE` supplies the passphrase without a prompt, for scripts and
tests. Interactively, prefer the prompt: an environment variable can end up in
shell history, process listings, or logs.

```sh
PIGEON_PASSPHRASE="$(secret-tool lookup pigeon vault)" pigeon send bob "Build finished"
```

Every command exits non-zero on failure and prints a `pigeon: …` error on
standard error.

## Security notes

- Names and messages from other people have control characters and
  bidirectional-override characters removed before they reach your terminal, so
  a message cannot rewrite your screen or disguise text.
- The relay sees which keys connect, when, and roughly how much traffic, but
  never message content. See [Delivery and Privacy](DELIVERY_AND_PRIVACY.md)
  and the [Security Model](SECURITY_MODEL.md).
- Pigeon has not been independently audited. Do not rely on it where a failure
  would put someone at risk.

## Troubleshooting

`wrong passphrase or tampered vault`
: The passphrase is wrong, or a vault file was changed. There is no recovery
  without the passphrase.

`another Pigeon process is using this vault`
: Another `pigeon` (perhaps a `listen` in another window) has the vault open.
  Close it first. This is deliberate: two processes would fork the ratchet
  state.

`no Pigeon identity here; run pigeon init first`
: Nothing exists at the vault location. Check `--home` and `PIGEON_HOME`.

`Still queued after 30s`
: None of the recipient's relays answered. The message is safe in your vault
  and is retried on the next run; `/status` shows how many items are waiting.

`Their card advertises no verified relay`
: The contact's card lists no relay with a valid signature, so there is nowhere
  to deliver to. Ask them for a fresh link.

`no contact matches` / `matches more than one contact`
: Use more of the name, or at least six characters of the identity key from
  `pigeon contacts`.
