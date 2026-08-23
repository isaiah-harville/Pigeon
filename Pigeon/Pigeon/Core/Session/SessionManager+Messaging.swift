//
//  SessionManager+Messaging.swift
//  Pigeon
//

import Foundation
import PigeonFFI

extension SessionManager {

  // MARK: - Inbound

  func handleInbound(_ data: Data, channel: TransportChannel) -> TransportMessageDisposition {
    guard let envelope = try? SessionEnvelope(decoding: data) else { return .consumed }
    guard envelope.recipient == myID else { return .consumed }  // not addressed to us

    // Locked (e.g. relaunched in the background — no Face ID prompt possible):
    // we can't decrypt or persist yet. Hold the envelope in memory and prompt
    // the user to unlock; the relay retains its copy too (we don't ack while
    // locked), so nothing is lost if we're killed before unlock.
    guard isUnlocked else {
      bufferWhileLocked(data, channel: channel)
      return .retryAfterRestart
    }

    guard isPersistenceHealthy else { return .retryAfterRestart }
    guard purgeExpiredIncomingRequests(now: Date()) else { return .retryAfterRestart }

    guard !blockedContactIDs.contains(envelope.sender) else { return .consumed }

    guard let (contact, admittedUnknown) = contactForInbound(envelope) else { return .consumed }
    let consumed = dispatchInbound(envelope, from: contact, channel: channel)
    removeRejectedUnknown(contact, ifAdmitted: admittedUnknown)
    return consumed ? .consumed : .retryAfterRestart
  }

  private func contactForInbound(_ envelope: SessionEnvelope) -> (Contact, Bool)? {
    if let known = contacts.first(where: { $0.id == envelope.sender }) { return (known, false) }
    let requestDates = contacts.compactMap { contact in
      contact.requestState == .incoming ? contact.requestCreatedAt : nil
    }
    guard Self.canAdmitIncomingRequest(existingDates: requestDates, now: Date()),
      envelope.type == .x3dhInit,
      let request = SessionInitiationPayload(decoding: envelope.payload),
      let card = ContactCard(scanned: request.contactCard),
      card.bundle.identityKey == envelope.sender,
      envelope.sender != myID
    else { return nil }
    let sanitized = DisplayName.sanitize(card.name)
    let contact = Contact(
      bundle: card.bundle, displayName: sanitized.isEmpty ? "Unnamed" : sanitized,
      relayURLs: card.relayURLs, prekeyBundle: card.prekeyBundle,
      verifiedInPerson: false, requestState: .incoming, requestCreatedAt: Date())
    contacts.append(contact)
    return (contact, true)
  }

  private func dispatchInbound(
    _ envelope: SessionEnvelope, from contact: Contact, channel: TransportChannel
  ) -> Bool {
    switch envelope.type {
    case .x3dhInit: return handleInitiation(envelope.payload, from: contact)
    case .message: return handleMessage(envelope.payload, from: contact, channel: channel)
    case .rehandshakeRequest:
      handleRehandshakeRequest(from: contact)
      return isPersistenceHealthy
    case .ack: return handleAck(envelope.payload, from: contact)
    case .control: return handleControl(envelope.payload, from: contact)
    // Olm is async-first: there is no interactive Noise handshake anymore, so a
    // `.handshake` envelope (only ever sent by the old protocol) is ignored.
    case .handshake: return true
    }
  }

  private func removeRejectedUnknown(_ contact: Contact, ifAdmitted admitted: Bool) {
    if admitted, sessions[contact.id] == nil {
      contacts.removeAll { $0.id == contact.id }
    }
  }

  /// Responder side of async first contact: a peer opened an Olm session against
  /// our published prekey (we may have been offline when they sent it).
  /// Reconstruct the session from the initiation, then process the `message`
  /// envelopes that follow normally.
  func handleInitiation(_ payload: Data, from contact: Contact) -> Bool {
    guard let request = SessionInitiationPayload(decoding: payload),
      let senderCard = ContactCard(scanned: request.contactCard),
      senderCard.bundle.identityKey == contact.id
    else {
      note(.sessionRejected)
      return true
    }
    let initiation = request.initiation
    // Only the lexicographic responder accepts initiations; if we're the
    // initiator we drive our own session and ignore a crossed initiation. A
    // one-sided request may start from either role.
    guard contact.requestState == .incoming || !isInitiator(toward: contact.id) else { return true }

    // A retransmit of the initiation we already processed: don't rebuild (that
    // would make a second session), but re-send the establishment ack — the peer
    // is resending precisely because our earlier ack was lost, and since we now
    // persist `lastInitiationIn` across relaunch we can no longer rely on
    // forgetting it to trigger a rebuild-and-reack. A *different* payload means
    // the peer genuinely restarted — fall through and rebuild.
    if resendAckForRepeatedInitiation(initiation, from: contact) { return true }

    guard let initiationDigest = freshInitiationDigest(initiation, from: contact) else {
      return true
    }

    guard let account else { return false }

    // Establish, then confirm the initiation's verified identity matches this
    // contact (constant-time inside ed25519 verification) — the binding check.
    guard let inbound = try? account.establishInbound(initiation: initiation),
      inbound.session.remoteIdentityKey() == contact.bundle.identityKey
    else {
      note(.sessionRejected)
      return true
    }

    lastInitiationIn[contact.id] = initiation
    acceptedInitiationDigests[contact.id, default: []].insert(initiationDigest)
    sessions[contact.id] = inbound.session
    establishedContactIDs.insert(contact.id)
    guard persist() else { return false }  // establishInbound may have consumed a one-time key
    note(.sessionEstablished)

    // The initiation's first plaintext is just the establishment sentinel; real
    // messages arrive as `.message` envelopes. Confirm establishment so the
    // initiator stops resending, even if no app message follows immediately.
    if let ack = try? inbound.session.encrypt(plaintext: Self.establishmentAck) {
      sendEnvelope(.ack, payload: ack, to: contact)
    }
    // Session-established event: flush anything we queued while waiting for
    // the initiation, now that we can encrypt to this contact.
    sendPending(to: contact)
    return true
  }

  private func resendAckForRepeatedInitiation(_ initiation: Data, from contact: Contact) -> Bool {
    guard initiation == lastInitiationIn[contact.id] else { return false }
    if let session = sessions[contact.id],
      let ack = try? session.encrypt(plaintext: Self.establishmentAck)
    {
      sendEnvelope(.ack, payload: ack, to: contact)
    }
    return true
  }

  private func freshInitiationDigest(_ payload: Data, from contact: Contact) -> Data? {
    guard let canonicalInitiation = try? canonicalizeInitiation(encoded: payload) else {
      note(.sessionRejected)
      return nil
    }
    let digest = InitiationReplayLedger.digest(canonicalInitiation)
    let acceptedDigests = acceptedInitiationDigests[contact.id, default: []]
    guard !acceptedDigests.contains(digest) else { return nil }
    guard acceptedDigests.count < InitiationReplayLedger.maximumEntriesPerContact else {
      note(.sessionRejected)
      return nil
    }
    return digest
  }

  func handleMessage(_ payload: Data, from contact: Contact, channel: TransportChannel) -> Bool {
    guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id) else {
      // We have no session for a contact that's messaging us — our state is
      // stale (we likely restarted). Trigger reconnection.
      requestRehandshake(with: contact)
      return true
    }
    guard let plaintext = try? session.decrypt(message: payload),
      var received = Self.decodeMessage(plaintext)
    else {
      note(.decryptionFailed)
      requestRehandshake(with: contact)
      return true
    }
    normalizeSystemEvent(&received, from: contact)
    // Deduplicate by the sender's message id (a retried message arrives twice).
    if conversationStore.contains(messageID: received.id, for: contact.id) {
      guard persistCrypto() else { return false }
    } else if shouldDiscardRequestMessage(received, from: contact) {
      // Decrypt to advance the authenticated ratchet, but retain exactly one
      // introductory message. Ack extras so they cannot create a retry loop.
      guard persistCrypto() else { return false }
    } else {
      if contact.requestState == .incoming,
        !received.system, received.event == nil,
        let index = contacts.firstIndex(where: { $0.id == contact.id })
      {
        contacts[index].introductionReceived = true
      }
      received.transport = channel
      guard record(received, for: contact.id) else { return false }

      // Surface a banner/notification only after the message and ratchet are durable.
      presenter.notifyIncoming(
        contactID: contact.id,
        title: contact.requestState == .incoming ? "Message Request" : contact.displayName,
        body: contact.requestState == .incoming ? "New message request" : received.text)
    }
    // The incoming message is durable, so its relay copy can be removed even if
    // persisting the newly encrypted end-to-end acknowledgement later fails.
    sendAck(messageID: received.id, to: contact)
    return true
  }

  private func normalizeSystemEvent(_ message: inout ChatMessage, from contact: Contact) {
    if message.event == .screenshot {
      message.text = Self.screenshotNotice(mine: false, contactName: contact.displayName)
    } else if message.event == .contactAccepted {
      message.text = "Message request accepted"
      acceptOutgoingRequest(from: contact.id)
    } else if message.event == .relayRecommendation {
      message.text = "\(contact.displayName) shared a relay"
    }
  }

  private func shouldDiscardRequestMessage(_ message: ChatMessage, from contact: Contact) -> Bool {
    guard contact.requestState == .incoming else { return false }
    if message.system || message.event != nil { return true }
    return contacts.first { $0.id == contact.id }?.introductionReceived == true
  }

  func sendAck(messageID: UUID, to contact: Contact) {
    guard let session = sessions[contact.id],
      let ciphertext = try? session.encrypt(plaintext: Data(messageID.uuidString.utf8))
    else { return }
    sendEnvelope(.ack, payload: ciphertext, to: contact)
  }

  func handleAck(_ payload: Data, from contact: Contact) -> Bool {
    guard let session = sessions[contact.id],
      let plaintext = try? session.decrypt(message: payload)
    else { return true }
    // Any decryptable ack proves the peer holds the session, so the initiation
    // has landed — stop resending it.
    pendingInitiation[contact.id] = nil
    // A message-id ack additionally confirms that message end-to-end — the only
    // proof of delivery we have — so mark it delivered; the establishment sentinel
    // confirms nothing further.
    if let idString = String(data: plaintext, encoding: .utf8),
      let id = UUID(uuidString: idString)
    {
      setDelivery(.delivered, messageID: id, contactID: contact.id)
    }
    return persist()
  }

  // MARK: - Transport mode (relay default; Bluetooth opt-in)

  /// Switches a chat between the relay (default) and Bluetooth, mirroring the
  /// change to the peer so both ends of the chat use the same link.
  func setChatUsesBluetooth(_ useBluetooth: Bool, for contact: Contact) {
    guard let current = contacts.first(where: { $0.id == contact.id }),
      current.requestState == .none
    else { return }
    guard bluetoothChatIDs.contains(contact.id) != useBluetooth else { return }
    applyTransport(useBluetooth: useBluetooth, for: contact.id, announce: true)
    sendTransportState(to: contact)
  }

  /// Applies a transport-mode change locally and adds a centered notice in the
  /// chat (matching how ephemeral announces itself). The relay notice names the
  /// host this side will actually use, so each end shows its own relay.
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
        text = "Switched to Local"
      } else if let host = relayHost(for: contactID) {
        text = "Switched to relay · \(host)"
      } else {
        text = "Switched to relay"
      }
      record(ChatMessage(mine: false, text: text, system: true), for: contactID)
    }
    persist()
    // Transport-switched event: resend unacked messages over the link this
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

  func handleControl(_ payload: Data, from contact: Contact) -> Bool {
    guard let session = sessions[contact.id],
      let plaintext = try? session.decrypt(message: payload),
      let command = plaintext.first
    else { return true }
    guard contact.requestState == .none else { return persistCrypto() }
    switch command {
    case 0x01, 0x02:
      guard plaintext.count == 2 else { return persistCrypto() }
      let value = plaintext[plaintext.index(after: plaintext.startIndex)] == 1
      if command == 0x01 {
        applyEphemeral(value, for: contact.id, announce: true)
      } else {
        applyTransport(useBluetooth: value, for: contact.id, announce: true)
      }
    case 0x03:
      guard let reaction = Self.decodeReaction(plaintext) else { return persistCrypto() }
      applyReaction(reaction.emoji, messageID: reaction.messageID, from: contact)
    default: break
    }
    return isPersistenceHealthy && persistCrypto()
  }

  /// Records a screenshot in the visible conversation and mirrors the event to
  /// that peer over the existing authenticated session. iOS reports screenshots
  /// after capture, so this is an audit notice rather than prevention.
  func reportScreenshotTaken() {
    guard let contactID = activeChatID,
      let contact = contacts.first(where: { $0.id == contactID })
    else { return }
    var event = ChatMessage(
      mine: true,
      text: Self.screenshotNotice(mine: true, contactName: contact.displayName),
      pending: true)
    event.system = true
    event.event = .screenshot
    event.transientOutbox = isEphemeral(contact)
    guard record(event, for: contact.id) else { return }
    armDeliveryDeadline(messageID: event.id, contactID: contact.id)
    if establishedContactIDs.contains(contact.id) {
      transmit(event, to: contact)
    } else {
      ensureEstablishing(contactID: contact.id)
    }
  }

  /// Recovers a lost/stale session. The initiator re-establishes; the responder
  /// asks the initiator to do so. Triggered by *network* input (an undecryptable
  /// message, a missing session for an inbound message), so it's rate-limited per
  /// contact: a spoofed flood can't drive endless resets or re-request spam.
  func requestRehandshake(with contact: Contact) {
    guard contact.requestState == .none else { return }
    guard rehandshakeGate.allow(contact.id, now: Date()) else { return }
    if isInitiator(toward: contact.id) {
      resetSession(for: contact.id)
      establishIfNeeded(contactID: contact.id)
    } else {
      sendEnvelope(.rehandshakeRequest, payload: Data(), to: contact)
    }
  }

  func handleRehandshakeRequest(from contact: Contact) {
    guard contact.requestState == .none else { return }
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
    // started. The request is unauthenticated (empty payload), so rate-limit the
    // destructive reset per contact — a spoofed `.rehandshakeRequest` flood then
    // costs at most one teardown per cooldown window rather than one per packet.
    // A genuinely lost peer simply re-requests after the window.
    guard establishedContactIDs.contains(contact.id) || sessions[contact.id] == nil else { return }
    guard rehandshakeGate.allow(contact.id, now: Date()) else { return }
    note(.reestablishmentRequested)
    resetSession(for: contact.id)
    establishIfNeeded(contactID: contact.id)
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
    guard let contact = contacts.first(where: { $0.id == contactID }),
      contact.requestState != .incoming,
      contact.requestState == .outgoing || isInitiator(toward: contactID)
    else { return }
    guard contact.prekeyBundle != nil else {
      // Olm is async-first with no interactive fallback, so without a published
      // prekey there is no way to open a session. (Every current QR card carries
      // one; this only bites a card produced without prekeys.)
      note(.missingPrekey)
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
      note(.sessionRejected)
      return
    }
    // The first plaintext is an establishment sentinel; the responder discards it
    // and real messages follow as `.message` envelopes (mirroring the old flow).
    guard
      let outbound = try? account.establishOutbound(
        peerBundle: peerBundle.encoded, firstPlaintext: Self.establishmentHello)
    else {
      note(.firstContactFailed)
      return
    }
    sessions[contact.id] = outbound.session
    guard let card = myCard,
      let initiationPayload = SessionInitiationPayload(
        initiation: outbound.initiation, contactCard: card.encoded()
      ).encoded()
    else { return }
    pendingInitiation[contact.id] = initiationPayload
    establishedContactIDs.insert(contact.id)
    sendEnvelope(.x3dhInit, payload: initiationPayload, to: contact)
    note(.firstContactStarted)
    sendPending(to: contact)  // deliver anything queued (initiation precedes it)
    if ephemeralContactIDs.contains(contact.id) { sendEphemeralState(to: contact) }
    if bluetoothChatIDs.contains(contact.id) { sendTransportState(to: contact) }
  }

  @discardableResult
  func sendEnvelope(_ type: EnvelopeType, payload: Data, to contact: Contact) -> Bool {
    let envelope = SessionEnvelope(
      type: type, sender: myID, recipient: contact.id, payload: payload)
    // App messages travel over the chat's chosen link (relay by default). Every
    // other envelope — initiations, acks, the control message that *syncs* the
    // link choice — floods both links so establishment and state sync stay
    // robust regardless of the selected transport. The recipient hint lets
    // the relay address this contact's mailbox directly; BLE ignores it.
    let channels: Set<TransportKind> =
      type == .message ? chatChannels(for: contact) : TransportKind.all
    // Every session-encrypted envelope (message/ack/control) and every initiation
    // advances or creates ratchet state the caller just produced. Persist the
    // crypto blob so the sealed session pickle never lags the live ratchet across
    // a relaunch; a lag would reuse Olm message indices. This is the crypto-only
    // fast path — conversation history is untouched here, so we don't re-encode
    // the bulk store. Idempotent for the rare non-encrypting envelopes (e.g.
    // rehandshake requests).
    guard persistCrypto() else { return false }
    mesh.send(envelope.encoded(), to: contact.id, over: channels)
    return true
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
