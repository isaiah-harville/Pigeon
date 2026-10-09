# Security review and audit readiness

[Security Model](SECURITY_MODEL.md) covers identity, cryptography, transport, and relay behavior.

## 7. Attacker Model

**Assume an attacker can:**
- Observe, record, replay, delay, drop, and reorder Bluetooth traffic.
- Operate or compromise relay devices in the mesh.
- **Operate or compromise an internet relay server** (if the user enables relay
  delivery): observe connection metadata — client IP/endpoints, timing, sizes,
  and that a sender is delivering to recipient key X — and drop, delay, or replay
  ciphertext. The relay **cannot** read content, impersonate a peer, or forge a
  trusted session.
- Operate a group's MLS coordinator: reorder, replay, equivocate about, withhold,
  or drop candidate commits and ciphertext. Signed receipts plus client-side MLS
  and policy verification protect integrity; availability remains attackable.
- Attempt pairing/identity impersonation and MITM.
- Tamper with any unauthenticated protocol field.
- Read app logs, crash reports, and unprotected on-disk state.
- Perform traffic analysis (timing, sizes, presence) on local radio.

**Assume an attacker cannot:**
- Break CryptoKit primitives (X25519, AES-GCM, ChaCha20-Poly1305, SHA-256, HMAC).
- Extract Keychain items from an uncompromised, locked device.
- Recover plaintext from a non-compromised endpoint after decryption.
- Defeat an out-of-band safety-number comparison performed honestly by users.

---

## 8. Known Limitations

- **Metadata is exposed.** BLE advertisements, packet timing, sizes, and mesh
  routing reveal communication patterns. No padding/cover traffic yet.
- **Relay metadata (if enabled).** An internet relay sees endpoints, timing,
  sizes, and sender→recipient-key mappings — never content. Sealed-sender,
  padding, and Tor routing to blunt this are planned, not implemented. Local
  transports avoid relay metadata; relay transports provide remote reach.
- **Endpoint trust.** A compromised/unlocked device defeats all guarantees.
- **No audit** (see below).
- **MLS integration is not audited.** OpenMLS supplies the protocol machinery,
  but Pigeon's identity binding, policy extension, coordinator protocol,
  transactional storage, and host event reduction remain project code requiring
  independent review and adversarial interoperability testing.
- **Key zeroization is limited at the FFI seam.** Ratchet and message keys live
  inside `vodozemac`, which zeroizes its own secrets on drop; but the seed and
  Olm account pickle cross the UniFFI boundary as plain bytes before being sealed
  at rest, and those transient copies are not yet explicitly wiped (§5.6).

---

## Audit Readiness — Pre-Audit Notes

**Pigeon has NOT undergone an independent security audit.** No "secure" or
"private" claim should be treated as verified until it has. This section lists
what an auditor should examine and what must be resolved first. It is the
authoritative to-do list for reaching audit readiness.

### Must-fix before an audit is meaningful
1. ~~**Bind the Olm identity key ↔ Ed25519 identity.**~~ ✅ **Implemented.**
   `IdentityBundle` carries Olm's Curve25519 identity key signed by the Ed25519
   identity; the QR payload is the signed bundle; `pigeon-core` rejects any
   established session whose Olm identity key does not equal the verified bundle's
   key. (Still subject to overall audit, but the gap is closed.)
2. **Audit the FFI/wire seam, not the ratchet primitives.** The Double Ratchet,
   session establishment, and message format are Olm as implemented by the
   audited `vodozemac` crate, so the audit target is Pigeon's *use* of it: the
   `pigeon-core` ↔ `vodozemac` boundary, the protobuf wire encode/decode in
   `wire.rs`, and the UniFFI bridge — not a re-audit of Olm itself.
3. ~~**Prekey replay / freshness.**~~ ✅ **Implemented.** Core tests record that
   one-time-key replay fails while fallback-key replay succeeds at the Olm layer.
   The app's encrypted, persistent initiation-digest ledger prevents an older
   accepted fallback initiation from replacing a newer live session, including
   across relaunch; fresh recovery initiations remain accepted.

### Should-address
4. **Skipped-key DoS bound.** Review Olm's bound on stored skipped message keys
   and the memory cost under adversarial gaps, as exposed through `pigeon-core`.
5. **Key lifetime & zeroization.** ⚠️ **Partially addressed** (§5.6): ratchet
   and message keys live inside `vodozemac`, which zeroizes its own secret
   material on drop. Still open on the Pigeon side: the seed and Olm account
   pickle cross the FFI boundary as plain bytes before being sealed at rest, so
   minimizing and wiping those transient copies remains.
6. **Constant-time comparisons.** ⚠️ **Partially addressed** (§5.6): Olm message
   authentication and signature checks are constant-time inside `vodozemac`.
   Remaining identity/public-key equality checks (the binding check) are over
   public values and left as ordinary comparisons (documented).
7. **Logging discipline.** Guarantee no key material, plaintext, or
   safety-relevant state reaches logs, crash reports, previews, or test output.
8. **Keychain access control.** Consider biometric/passcode gating
   (`SecAccessControl`) for identity-key use.
9. **At-rest storage.** Encryption key derivation, ephemeral-mode guarantees,
   and secure deletion.

### Metadata / traffic analysis (design-level)
10. **Padding & cover traffic** to blunt size/timing analysis.
11. **Advertisement/identifier rotation** to limit device tracking over BLE.
12. **Relay metadata minimization.** Sealed-sender addressing (so the relay
    cannot see the sender), uniform padding, and optional Tor routing to hide
    client IPs.

### Relay transport (new surface; only when remote delivery is enabled)
13. **Relay stays zero-knowledge.** Verify the relay only ever handles opaque
    ciphertext addressed by recipient key, with no field it can use to read,
    link, or tamper with content beyond drop/delay/replay.
14. **Replay/freshness across the relay.** Store-and-forward over a relay must
    not widen the prekey/message replay surface (ties to item 3).
15. **Relay abuse & retention.** ⚠️ **Partially addressed.** Storage is now
    bounded on every axis: per-envelope size, per-mailbox queue depth, mailbox
    count (`PIGEON_RELAY_MAX_MAILBOXES`), a global ciphertext ceiling
    (`PIGEON_RELAY_MAX_TOTAL_BYTES`, enforced by evicting from the *largest*
    mailbox so a flooder pays for its own pressure), age expiry, a bounded
    per-subscriber outbound channel (a backed-up reader is skipped, never
    buffered), and per-mailbox / total caps on registered push tokens. Still
    open: mailboxes remain
    authentication-free by design, so there is no per-sender rate limit — a
    flooder can still consume its own share of the ceiling and force eviction
    churn. No plaintext, keys, or linkable logs server-side.
16. **Transport authenticity.** A malicious relay must not be able to forge
    "delivered" state or inject packets that bypass mesh dedup/auth.

### What an auditor should focus on
- Pigeon's *use* of Olm via `vodozemac`: the `pigeon-core` session API, the
  protobuf wire encode/decode, and the UniFFI bridge — rather than re-auditing
  the Olm ratchet primitives themselves.
- Domain separation of Pigeon's own derived values (identity binding signature,
  safety-number derivation).
- The identity ↔ Olm Curve25519 binding (item 1) and the trust-establishment UX.
- That every field influencing decryption, trust, routing, or replay is
  authenticated.

---

## Contributor Review Checklist

- Are all fields influencing decryption, trust, routing, or replay authenticated?
- Are all derived keys domain-separated by protocol context?
- Is any private material logged, serialized, previewed, or emitted in tests?
- Does the change preserve identity continuity and keep resets explicit?
- Are replay, out-of-order, and dropped-message paths tested?
- Does the UI avoid implying a peer is verified before safety-number comparison?
- Does transport/mesh code treat all Bluetooth metadata as public?
- Does new crypto compose CryptoKit primitives rather than reimplement them?
```
