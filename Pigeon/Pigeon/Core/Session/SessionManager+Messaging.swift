//
//  SessionManager+Messaging.swift
//  Pigeon
//

import Foundation
import PigeonFFI

extension SessionManager {

  // MARK: - Inbound

  func handleInbound(_ data: Data, channel: TransportChannel) {
    guard let envelope = try? SessionEnvelope(decoding: data) else { return }
    guard envelope.recipient == myID else { return }  // not addressed to us

    // Locked (e.g. relaunched in the background — no Face ID prompt possible):
    // we can't decrypt or persist yet. Hold the envelope in memory and prompt
    // the user to unlock; the relay retains its copy too (we don't ack while
    // locked), so nothing is lost if we're killed before unlock.
    guard isUnlocked else {
      bufferWhileLocked(data, channel: channel)
      return
    }

    guard let contact = contacts.first(where: { $0.id == envelope.sender }) else { return }
    switch envelope.type {
    case .x3dhInit: handleInitiation(envelope.payload, from: contact)
    case .message: handleMessage(envelope.payload, from: contact, channel: channel)
    case .rehandshakeRequest: handleRehandshakeRequest(from: contact)
    case .ack: handleAck(envelope.payload, from: contact)
    case .control: handleControl(envelope.payload, from: contact)
    // Olm is async-first: there is no interactive Noise handshake anymore, so a
    // `.handshake` envelope (only ever sent by the old protocol) is ignored.
    case .handshake: break
    }
  }

  /// Responder side of async first contact: a peer opened an Olm session against
  /// our published prekey (we may have been offline when they sent it).
  /// Reconstruct the session from the initiation, then process the `message`
  /// envelopes that follow normally.
  func handleInitiation(_ payload: Data, from contact: Contact) {
    // Only the lexicographic responder accepts initiations; if we're the
    // initiator we drive our own session and ignore a crossed initiation.
    guard !isInitiator(toward: contact.id) else { return }

    // A retransmit of the initiation we already processed: don't rebuild (that
    // would make a second session), but re-send the establishment ack — the peer
    // is resending precisely because our earlier ack was lost, and since we now
    // persist `lastInitiationIn` across relaunch we can no longer rely on
    // forgetting it to trigger a rebuild-and-reack. A *different* payload means
    // the peer genuinely restarted — fall through and rebuild.
    if payload == lastInitiationIn[contact.id] {
      if let session = sessions[contact.id],
        let ack = try? session.encrypt(plaintext: Self.establishmentAck)
      {
        sendEnvelope(.ack, payload: ack, to: contact)
      }
      return
    }

    guard let account else { return }

    // Establish, then confirm the initiation's verified identity matches this
    // contact (constant-time inside ed25519 verification) — the binding check.
    guard let inbound = try? account.establishInbound(initiation: payload),
      inbound.session.remoteIdentityKey() == contact.bundle.identityKey
    else {
      note(sessionRejectedMessage(for: contact))
      return
    }

    lastInitiationIn[contact.id] = payload
    sessions[contact.id] = inbound.session
    establishedContactIDs.insert(contact.id)
    persist()  // establishInbound may have consumed a one-time key
    note("Secure session established with \"\(contact.displayName)\" (async first contact)")

    // The initiation's first plaintext is just the establishment sentinel; real
    // messages arrive as `.message` envelopes. Confirm establishment so the
    // initiator stops resending, even if no app message follows immediately.
    if let ack = try? inbound.session.encrypt(plaintext: Self.establishmentAck) {
      sendEnvelope(.ack, payload: ack, to: contact)
    }
    // Session-established event (#82): flush anything we queued while waiting for
    // the initiation, now that we can encrypt to this contact.
    sendPending(to: contact)
  }

  func handleMessage(_ payload: Data, from contact: Contact, channel: TransportChannel) {
    guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id) else {
      // We have no session for a contact that's messaging us — our state is
      // stale (we likely restarted). Trigger reconnection.
      requestRehandshake(with: contact)
      return
    }
    guard let plaintext = try? session.decrypt(message: payload),
      var received = Self.decodeMessage(plaintext)
    else {
      note("Decrypt failed from \"\(contact.displayName)\" — re-establishing")
      requestRehandshake(with: contact)
      return
    }
    // Acknowledge every delivery (even duplicates) so the sender stops retrying.
    sendAck(messageID: received.id, to: contact)
    // Deduplicate by the sender's message id (a retried message arrives twice).
    if conversationStore.contains(messageID: received.id, for: contact.id) { return }
    received.transport = channel
    record(received, for: contact.id)

    // Surface a banner/notification unless the user is actively viewing this chat.
    presenter.notifyIncoming(
      contactID: contact.id, title: contact.displayName, body: received.text)
  }

  func sendAck(messageID: UUID, to contact: Contact) {
    guard let session = sessions[contact.id],
      let ciphertext = try? session.encrypt(plaintext: Data(messageID.uuidString.utf8))
    else { return }
    sendEnvelope(.ack, payload: ciphertext, to: contact)
  }

  func handleAck(_ payload: Data, from contact: Contact) {
    guard let session = sessions[contact.id],
      let plaintext = try? session.decrypt(message: payload)
    else { return }
    // Any decryptable ack proves the peer holds the session, so the initiation
    // has landed — stop resending it.
    pendingInitiation[contact.id] = nil
    // A message-id ack additionally clears that message's pending flag; the
    // establishment sentinel clears nothing further.
    if let idString = String(data: plaintext, encoding: .utf8),
      let id = UUID(uuidString: idString)
    {
      setPending(false, messageID: id, contactID: contact.id)
    }
    persist()
  }

  // MARK: - Transport mode (relay default; Bluetooth opt-in)

  /// Switches a chat between the relay (default) and Bluetooth, mirroring the
  /// change to the peer so both ends of the chat use the same link (#24).
  func setChatUsesBluetooth(_ useBluetooth: Bool, for contact: Contact) {
    guard bluetoothChatIDs.contains(contact.id) != useBluetooth else { return }
    applyTransport(useBluetooth: useBluetooth, for: contact.id, announce: true)
    sendTransportState(to: contact)
  }

  /// Applies a transport-mode change locally and adds a centered notice in the
  /// chat (matching how ephemeral announces itself). The relay notice names the
  /// host this side will actually use, so each end shows its own relay (#24).
  func applyTransport(useBluetooth: Bool, for contactID: Data, announce: Bool) {
    let changed = bluetoothChatIDs.contains(contactID) != useBluetooth
    if useBluetooth {
      bluetoothChatIDs.insert(contactID)
    } else {
      bluetoothChatIDs.remove(contactID)
    }
    if changed && announce {
      let text: String
      if useBluetooth {
        text = "Switched to Bluetooth"
      } else if let host = relayHost(for: contactID) {
        text = "Switched to relay · \(host)"
      } else {
        text = "Switched to relay"
      }
      record(ChatMessage(mine: false, text: text, system: true), for: contactID)
    }
    persist()
    // Transport-switched event (#82): resend unacked messages over the link this
    // chat now uses, so a switch flushes pending immediately (replacing the
    // timer's eventual retry). `sendPending` no-ops until the session exists.
    if changed, let contact = contacts.first(where: { $0.id == contactID }) {
      sendPending(to: contact)
    }
  }

  /// Sends our current transport choice for this chat to the peer (encrypted).
  func sendTransportState(to contact: Contact) {
    guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id) else {
      return
    }
    let byte: UInt8 = bluetoothChatIDs.contains(contact.id) ? 1 : 0
    let command = Data([0x02, byte])  // 0x02 = transport cmd (1 = Bluetooth, 0 = relay)
    guard let ciphertext = try? session.encrypt(plaintext: command) else { return }
    sendEnvelope(.control, payload: ciphertext, to: contact)
  }

  func handleControl(_ payload: Data, from contact: Contact) {
    guard let session = sessions[contact.id],
      let plaintext = try? session.decrypt(message: payload),
      let command = plaintext.first
    else { return }
    switch command {
    case 0x01, 0x02:
      guard plaintext.count == 2 else { return }
      let value = plaintext[plaintext.index(after: plaintext.startIndex)] == 1
      if command == 0x01 {
        applyEphemeral(value, for: contact.id, announce: true)
      } else {
        applyTransport(useBluetooth: value, for: contact.id, announce: true)
      }
    case 0x03:
      guard let reaction = Self.decodeReaction(plaintext) else { return }
      applyReaction(reaction.emoji, messageID: reaction.messageID, from: contact)
    default: break
    }
  }

  /// Recovers a lost/stale session. The initiator re-establishes; the responder
  /// asks the initiator to do so.
  func requestRehandshake(with contact: Contact) {
    if isInitiator(toward: contact.id) {
      resetSession(for: contact.id)
      establishIfNeeded(contactID: contact.id)
    } else {
      sendEnvelope(.rehandshakeRequest, payload: Data(), to: contact)
    }
  }

  func handleRehandshakeRequest(from contact: Contact) {
    guard isInitiator(toward: contact.id) else { return }  // only the initiator can start
    // An initiation we sent is still in flight (not yet acked): just resend it
    // rather than resetting the session we just stood up. Clobbering it would
    // orphan any message the peer already encrypted against that session and
    // restart the handshake race — the exact wedge behind the relaunch bug.
    if pendingInitiation[contact.id] != nil {
      sendPending(to: contact)
      return
    }
    // Otherwise re-establish only if we're established (peer lost it) or never
    // started.
    if establishedContactIDs.contains(contact.id) || sessions[contact.id] == nil {
      note("\"\(contact.displayName)\" requested re-establishment")
      resetSession(for: contact.id)
      establishIfNeeded(contactID: contact.id)
    }
  }

  // MARK: - Establishment (async-first, prekey-based)

  func isInitiator(toward contactID: Data) -> Bool {
    myID.lexicographicallyPrecedes(contactID)
  }

  /// Drives establishment for the initiator: open an Olm session against the
  /// peer's published prekey and send the initiation. (The responder waits for
  /// that initiation; it cannot start one itself.)
  func establishIfNeeded(contactID: Data) {
    guard !establishedContactIDs.contains(contactID) else { return }
    guard isInitiator(toward: contactID),
      let contact = contacts.first(where: { $0.id == contactID })
    else { return }
    guard contact.prekeyBundle != nil else {
      // Olm is async-first with no interactive fallback, so without a published
      // prekey there is no way to open a session. (Every current QR card carries
      // one; this only bites a card produced without prekeys.)
      note("Can't reach \"\(contact.displayName)\": no prekey in their code")
      return
    }
    if sessions[contactID] == nil {
      establishViaPrekey(contact)
    }
  }

  /// Initiator side of async first contact. Builds the Olm session from the
  /// peer's published prekey, marks it established (the binding is enforced by
  /// `establishOutbound`), and emits the initiation envelope (the peer's identity
  /// bundle plus the first Olm pre-key message). The initiation is retained
  /// (`pendingInitiation`) and resent until the peer acks, surviving loss and a
  /// peer that's offline for a while. Queued messages are delivered right after.
  func establishViaPrekey(_ contact: Contact) {
    guard let account, let peerBundle = contact.prekeyBundle else { return }
    // Defense-in-depth binding check (the card scanner already verified it): the
    // prekey bundle's identity must equal the verified contact.
    guard peerBundle.identityKey == contact.bundle.identityKey else {
      note(sessionRejectedMessage(for: contact))
      return
    }
    // The first plaintext is an establishment sentinel; the responder discards it
    // and real messages follow as `.message` envelopes (mirroring the old flow).
    guard
      let outbound = try? account.establishOutbound(
        peerBundle: peerBundle.encoded, firstPlaintext: Self.establishmentHello)
    else {
      note("First contact failed with \"\(contact.displayName)\"")
      return
    }
    sessions[contact.id] = outbound.session
    pendingInitiation[contact.id] = outbound.initiation
    establishedContactIDs.insert(contact.id)
    sendEnvelope(.x3dhInit, payload: outbound.initiation, to: contact)
    note("→ first contact to \"\(contact.displayName)\"")
    sendPending(to: contact)  // deliver anything queued (initiation precedes it)
    if ephemeralContactIDs.contains(contact.id) { sendEphemeralState(to: contact) }
    if bluetoothChatIDs.contains(contact.id) { sendTransportState(to: contact) }
  }

  func sendEnvelope(_ type: EnvelopeType, payload: Data, to contact: Contact) {
    let envelope = SessionEnvelope(
      type: type, sender: myID, recipient: contact.id, payload: payload)
    // App messages travel over the chat's chosen link (relay by default). Every
    // other envelope — initiations, acks, the control message that *syncs* the
    // link choice — floods both links so establishment and state sync stay
    // robust regardless of the selected transport (#24). The recipient hint lets
    // the relay address this contact's mailbox directly; BLE ignores it.
    let channels: Set<TransportKind> =
      type == .message ? chatChannels(for: contact) : TransportKind.all
    mesh.send(envelope.encoded(), to: contact.id, over: channels)
    // Every session-encrypted envelope (message/ack/control) and every initiation
    // advances or creates ratchet state the caller just produced. Persist so the
    // sealed session pickle never lags the live ratchet across a relaunch; a lag
    // would reuse Olm message indices. Cheap and idempotent for the rare
    // non-encrypting envelopes (e.g. rehandshake requests).
    persist()
  }

  func sessionRejectedMessage(for contact: Contact) -> String {
    """
    Session REJECTED with "\(contact.displayName)": identity does not match \
    verified contact
    """
  }

  // MARK: - Initiation wire form

  /// The establishment sentinel the initiator encrypts as the Olm pre-key
  /// message's first plaintext; the responder recovers and discards it. Empty,
  /// so it never collides with an encoded app message. The initiation itself is
  /// an opaque `pigeon.wire.v1.Initiation` blob produced by `establishOutbound`
  /// and consumed by `establishInbound` — the app no longer frames it.
  static let establishmentHello = Data()
  /// What the responder encrypts back to confirm establishment (a single byte,
  /// never a valid message-id ack).
  static let establishmentAck = Data([0x00])

}
