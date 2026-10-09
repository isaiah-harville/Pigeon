# Shareable group invites

## Goal and scope

For Pigeon 1.4.0, an existing group of at most 128 members may accept join requests from a link or QR. A public invite lets the issuing admin's app process valid requests automatically. A private invite requires explicit admin approval. Neither mode requires a Pigeon account. A join cannot complete while all authorized admins are offline; the request waits for one to return.

## Invite and request

An authorized admin creates a random, revocable invite for one group. The share URL fragment carries a versioned bearer secret, group and relay locator, coordinator public key, mode, expiry, and an encrypted request inbox public key. URL fragments avoid sending the secret in a normal HTTP request to the relay. The app warns before a public link is shared that possession permits a join request and that link holders can redistribute it.

The issuer creates a dedicated, short-lived Olm account for each invite using the existing `vodozemac` implementation. The link contains its public Olm identity and fallback prekey, while the private account pickle stays inside the presence-gated core checkpoint and is deleted on invite revocation or expiry. This account is a transport inbox key, not the user's long-term Pigeon identity. The joiner verifies the invite format and pinned coordinator key, creates root-bound MLS join material, and submits a request encrypted to the invite account. The request includes a fresh request ID and a reply address. The relay stores only bounded opaque ciphertext and delivery metadata, with durable write-before-ack and expiry. It cannot grant membership or read the request. The issuer's long-term root identity does not appear in a public invite, and the link does not expose the private inbox key.

The admin app durably classifies each request once. Public mode automatically accepts while the invite is current and the group is below 128 members. Private mode shows the request for approval. Declining, expiry, rotation, removal of the issuing admin, and a full group stop future additions. The admin stages the existing MLS Add and Welcome flow; coordinator receipts serialize concurrent joins. The joiner validates the resulting MLS policy, group ID, and coordinator key before showing membership. The app displays pending, approved, rejected, expired, and full-group states without claiming a queued request is membership.

Invite revocation and use limits are issuer-side controls. A malicious current admin could already add an arbitrary member through the existing protocol, so the link does not promise protection from that admin. Current members still verify every MLS Add and capability rotation. Previously joined members remain members after link revocation.

## Invariants and tests

- A forged, replayed, expired, revoked, wrong-group, or wrong-coordinator request creates no membership.
- A link from a removed admin cannot add members.
- Concurrent requests cannot exceed 128 members or reuse one key package.
- A pending request and the issuer's acceptance survive app and relay restarts.
- Private requests never auto-accept; public requests follow the advertised policy.
- Relay failure or a missing admin leaves a visible pending request and never fabricates a Welcome.
- Invitee identity and join material stay encrypted from the relay; a public link does not disclose an admin's long-term identity.

This is a separate protocol change from relay registration admission. It requires a wire schema and core policy update, a bounded durable invite inbox, FFI and app flows, and adversarial crash and replay tests. Physical multi-device and locked-delivery validation remain release gates.
