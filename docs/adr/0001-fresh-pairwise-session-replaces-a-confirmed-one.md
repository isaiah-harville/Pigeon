# 0001. A fresh pairwise session from a peer replaces a confirmed one

- Status: Accepted
- Date: 2026-11-09

## Context

`pigeon-core` used to reject every pre-key message that matched no stored
session once a session with that peer had received a message. The aim was that
a spoofed or replayed envelope could never tear down a working session.

That rule deadlocked real users. If Alice removed Bob and added him again, or
lost her pairwise state while keeping her identity, she opened a new session.
Bob still held the old confirmed one and rejected Alice's new session. Alice
could not decrypt Bob's messages on the old session. Neither side could reach
the other until both removed and re-added the contact.

Spoofing a pre-key message is already impossible. Olm opens an inbound session
only through a triple Diffie-Hellman that needs the sender's Curve25519 identity
key, and Pigeon binds that key to the peer's Ed25519 root. The real risk is
replay. Pigeon's prekey is a reusable fallback key, so Olm accepts the same
pre-key message again. An attacker who captured an old opening message could use
it to reopen a dead session and show its first message again.

## Decision

A pre-key message from a peer that matches no stored session replaces that
peer's sessions when one of them is confirmed. The core records the id of every
session it drops (on replacement and on contact removal) in the checkpoint's
`retired_pairwise_session_ids`, and refuses any pre-key message that carries a
retired id. The list keeps the newest 1,024 ids. Before any session is
confirmed, the glare rule is unchanged: at most two sessions per peer.

## Alternatives considered

- **Keep rejecting and tell users to re-add on both sides**: it is the deadlock.
  Neither side can tell what went wrong, and the remedy needs both people.
- **Keep the session when a contact is removed**: fixes only removal, not lost
  state. Removing a contact would also stop forgetting its keys.
- **Send a reset message on the old session before removing**: it never reaches
  a peer whose state is already gone, and it tells the peer they were removed.
- **Rotate the fallback key on every replacement**: it invalidates the prekey in
  every QR card already shared.

## Consequences

- Removing and re-adding a contact, or losing local pairwise state, heals on the
  next message from the side that lost it. Messages the other side sent on the
  old session in the meantime are lost; their senders see them as undelivered.
- A replay of a session dropped after this change is refused, including after
  the receiver removes and re-adds the sender, which used to reopen it.
- A replayed pre-key message for a session this client never stored, or whose
  id has aged out of the 1,024-entry list, can still replace a confirmed
  session. That costs availability (the chat breaks until one side sends a new
  message after re-adding), not confidentiality or authenticity: the opener
  still needs the peer's identity key.
