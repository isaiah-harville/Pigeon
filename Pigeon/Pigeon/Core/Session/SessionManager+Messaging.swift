//
//  SessionManager+Messaging.swift
//  Pigeon
//

import Foundation
import PigeonCrypto
import PigeonMesh

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
    case .handshake: handleHandshake(envelope.payload, from: contact)
    case .message: handleMessage(envelope.payload, from: contact, channel: channel)
    case .rehandshakeRequest: handleRehandshakeRequest(from: contact)
    case .ack: handleAck(envelope.payload, from: contact)
    case .control: handleControl(envelope.payload, from: contact)
    }
  }

  func handleHandshake(_ payload: Data, from contact: Contact) {
    // Stop-and-wait retransmit: a duplicate of the last handshake message we
    // processed means our reply was lost — resend the same reply rather than
    // churning a new session (which would move the target and never converge).
    if payload == lastHandshakeIn[contact.id] {
      if !establishedContactIDs.contains(contact.id), let reply = lastHandshakeOut[contact.id] {
        sendEnvelope(.handshake, payload: reply, to: contact)
      }
      return
    }
    lastHandshakeIn[contact.id] = payload

    if isInitiator(toward: contact.id) {
      // We drive; this is the responder's reply on our stable session.
      guard let session = sessions[contact.id] else { return }  // not started; retry will
      guard (try? session.readHandshakeMessage(payload)) != nil else {
        return  // unreadable reply — ignore, keep our session intact
      }
      note("← handshake reply from \"\(contact.displayName)\"")
      pump(session, with: contact)
    } else {
      // We respond. A *new* handshake while established means the peer
      // restarted and lost its session — drop ours and re-handshake.
      if establishedContactIDs.contains(contact.id) {
        establishedContactIDs.remove(contact.id)
        sessions[contact.id] = nil
        note("Peer \"\(contact.displayName)\" restarted; re-establishing")
      }
      var session = sessions[contact.id] ?? makeResponder(for: contact)
      if (try? session.readHandshakeMessage(payload)) == nil {
        session = makeResponder(for: contact)
        guard (try? session.readHandshakeMessage(payload)) != nil else {
          note("Handshake read failed from \"\(contact.displayName)\"")
          return
        }
      }
      pump(session, with: contact)
    }
  }

  func handleMessage(_ payload: Data, from contact: Contact, channel: TransportChannel) {
    guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id) else {
      // We have no session for a contact that's messaging us — our state is
      // stale (we likely restarted). Trigger reconnection.
      requestRehandshake(with: contact)
      return
    }
    guard let plaintext = try? session.decrypt(payload),
      let (id, text) = Self.decodeMessage(plaintext)
    else {
      note("Decrypt failed from \"\(contact.displayName)\" — re-establishing")
      requestRehandshake(with: contact)
      return
    }
    // Acknowledge every delivery (even duplicates) so the sender stops retrying.
    sendAck(messageID: id, to: contact)
    // Deduplicate by the sender's message id (a retried message arrives twice).
    if conversations[contact.id]?.contains(where: { $0.id == id }) == true { return }
    var received = ChatMessage(mine: false, text: text)
    received.id = id
    received.transport = channel
    record(received, for: contact.id)

    // Surface a notification unless the user is actively viewing this chat.
    guard !(isAppActive && activeChatID == contact.id) else { return }
    if isAppActive {
      showBanner(title: contact.displayName, body: text)
    } else {
      onIncomingNotification?()  // local notification while backgrounded
    }
  }

  func showBanner(title: String, body: String) {
    let banner = InAppBanner(title: title, body: body)
    self.banner = banner
    Task {
      try? await Task.sleep(for: .seconds(3))
      if self.banner == banner { self.banner = nil }
    }
  }

  func sendAck(messageID: UUID, to contact: Contact) {
    guard let session = sessions[contact.id],
      let ciphertext = try? session.encrypt(Data(messageID.uuidString.utf8))
    else { return }
    sendEnvelope(.ack, payload: ciphertext, to: contact)
  }

  func handleAck(_ payload: Data, from contact: Contact) {
    guard let session = sessions[contact.id],
      let plaintext = try? session.decrypt(payload),
      let idString = String(data: plaintext, encoding: .utf8),
      let id = UUID(uuidString: idString)
    else { return }
    setPending(false, messageID: id, contactID: contact.id)
    persist()
  }

  /// Recovers a lost/stale session. The initiator restarts the handshake; the
  /// responder asks the initiator to do so.
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
    // Restart only if we're established (peer lost it) or never started; if a
    // handshake is already in progress, let it finish rather than clobber it.
    if establishedContactIDs.contains(contact.id) || sessions[contact.id] == nil {
      note("\"\(contact.displayName)\" requested re-handshake")
      resetSession(for: contact.id)
      establishIfNeeded(contactID: contact.id)
    }
  }

  // MARK: - Handshake driving

  func isInitiator(toward contactID: Data) -> Bool {
    myID.lexicographicallyPrecedes(contactID)
  }

  func establishIfNeeded(contactID: Data) {
    guard !establishedContactIDs.contains(contactID) else { return }
    guard isInitiator(toward: contactID),
      let contact = contacts.first(where: { $0.id == contactID })
    else { return }

    if sessions[contactID] == nil {
      // Start a fresh handshake and remember msg1 for retries.
      let session = SecureSession.initiator(localStatic: identity.noiseStaticKey)
      sessions[contactID] = session
      guard let msg1 = try? session.writeHandshakeMessage() else {
        note("Failed to start handshake with \"\(contact.displayName)\"")
        return
      }
      pendingMsg1[contactID] = msg1
      sendEnvelope(.handshake, payload: msg1, to: contact)
      note("→ handshake to \"\(contact.displayName)\"")
    } else if let msg1 = pendingMsg1[contactID] {
      // Resend the SAME msg1 (peer may not have been a contact yet / it was lost).
      sendEnvelope(.handshake, payload: msg1, to: contact)
    }
  }

  func makeResponder(for contact: Contact) -> SecureSession {
    let session = SecureSession.responder(localStatic: identity.noiseStaticKey)
    sessions[contact.id] = session
    return session
  }

  /// Sends any handshake messages this side currently owes, then finalizes.
  func pump(_ session: SecureSession, with contact: Contact) {
    while !session.isEstablished {
      guard let message = try? session.writeHandshakeMessage() else { break }
      sendEnvelope(.handshake, payload: message, to: contact)
      lastHandshakeOut[contact.id] = message  // for stop-and-wait retransmit
      note("→ handshake step to \"\(contact.displayName)\"")
    }
    finalize(session, with: contact)
  }

  /// Once Noise completes, verify the handshake's static key matches the
  /// verified contact bundle before trusting the channel.
  func finalize(_ session: SecureSession, with contact: Contact) {
    guard session.isEstablished, !establishedContactIDs.contains(contact.id) else { return }
    // The binding check is an authentication decision over key bytes, so compare
    // in constant time (both keys are public, but this avoids leaking how many
    // leading bytes match a forged static key).
    guard let remoteStatic = session.remoteStaticKey,
      ConstantTime.equals(remoteStatic, contact.bundle.staticKey),
      contact.bundle.isValid()
    else {
      sessions[contact.id] = nil
      note(sessionRejectedMessage(for: contact))
      return
    }
    establishedContactIDs.insert(contact.id)
    note("Secure session established with \"\(contact.displayName)\"")
    sendPending(to: contact)  // deliver anything queued while out of range
    if ephemeralContactIDs.contains(contact.id) { sendEphemeralState(to: contact) }  // re-sync ephemeral
  }

  func sendEnvelope(_ type: EnvelopeType, payload: Data, to contact: Contact) {
    let envelope = SessionEnvelope(
      type: type, sender: myID, recipient: contact.id, payload: payload)
    // The recipient hint lets the relay address this contact's mailbox directly;
    // BLE ignores it and floods.
    mesh.send(envelope.encoded(), to: contact.id)
  }

  func sessionRejectedMessage(for contact: Contact) -> String {
    """
    Session REJECTED with "\(contact.displayName)": static key does not match \
    verified identity
    """
  }

  // MARK: - Retry

  func startRetryLoop() {
    retryTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
      guard let self else { return }
      Task { @MainActor in self.tick() }
    }
  }

  func tick() {
    for contact in contacts {
      if establishedContactIDs.contains(contact.id) {
        sendPending(to: contact)  // retry unacked messages until they land
      } else {
        ensureEstablishing(contactID: contact.id)
      }
    }
  }

  /// Drives (re)establishment for one contact according to our role: the
  /// initiator (re)sends msg1; the responder nudges the initiator to start.
  func ensureEstablishing(contactID: Data) {
    guard !establishedContactIDs.contains(contactID) else { return }
    if isInitiator(toward: contactID) {
      establishIfNeeded(contactID: contactID)
    } else if let contact = contacts.first(where: { $0.id == contactID }) {
      sendEnvelope(.rehandshakeRequest, payload: Data(), to: contact)
    }
  }

  // MARK: - Locked receipt

  /// Upper bound on envelopes buffered while locked (memory only).
  private static let maxLockedInbox = 256

  /// Buffers an envelope received while locked and prompts the user to unlock.
  /// The notification is content-free and fires once per locked session
  /// (coalesced) so a flood of deposits can't spam notifications.
  func bufferWhileLocked(_ data: Data, channel: TransportChannel) {
    lockedInbox.append((data, channel))
    if lockedInbox.count > Self.maxLockedInbox {
      lockedInbox.removeFirst(lockedInbox.count - Self.maxLockedInbox)
    }
    if !notifiedWhileLocked {
      notifiedWhileLocked = true
      onIncomingNotification?()
    }
  }

  /// Replays envelopes buffered while locked, now that we can decrypt and
  /// persist. Called from `attachStore` once the vault is open.
  func drainLockedInbox() {
    guard !lockedInbox.isEmpty else { return }
    let buffered = lockedInbox
    lockedInbox.removeAll()
    for (data, channel) in buffered { handleInbound(data, channel: channel) }
  }

  // MARK: - Store-and-forward

  /// (Re)sends every unacknowledged outbound message for a contact. Pending is
  /// cleared only when the peer ACKs, so a message survives disconnects and
  /// lost packets; duplicates are deduplicated by the recipient.
  func sendPending(to contact: Contact) {
    guard establishedContactIDs.contains(contact.id) else { return }
    let pending = (conversations[contact.id] ?? []).filter { $0.mine && $0.pending }
    for message in pending {
      transmit(message, to: contact)
    }
  }

  /// Flips a message's pending flag in both the in-memory view and the disk mirror.
  func setPending(_ pending: Bool, messageID: UUID, contactID: Data) {
    if let index = conversations[contactID]?.firstIndex(where: { $0.id == messageID }) {
      conversations[contactID]?[index].pending = pending
    }
    if let index = persistedConversations[contactID]?.firstIndex(where: { $0.id == messageID }) {
      persistedConversations[contactID]?[index].pending = pending
    }
  }

  // MARK: - Logging & persistence

  func note(_ message: String) {
    log.append(message)
    if log.count > 200 { log.removeFirst(log.count - 200) }
  }

  /// Appends a message to the in-memory view, and to the on-disk mirror unless
  /// the chat is ephemeral, then persists.
  func record(_ message: ChatMessage, for contactID: Data) {
    conversations[contactID, default: []].append(message)
    if !ephemeralContactIDs.contains(contactID) {
      persistedConversations[contactID, default: []].append(message)
    }
    persist()
  }

  /// Writes contacts, the on-disk conversation mirror, and ephemeral flags to
  /// the encrypted store (no-op before unlock).
  func persist() {
    guard let store, isUnlocked else { return }
    let persistedContacts = contacts.map { contact in
      PersistedContact(
        name: contact.displayName, bundle: contact.bundle.encoded(),
        relayURLs: contact.relayURLs.map(\.absoluteString))
    }
    var conversationsByKey: [String: [ChatMessage]] = [:]
    for (id, messages) in persistedConversations {
      conversationsByKey[id.base64EncodedString()] = messages
    }
    store.save(
      PersistedState(
        contacts: persistedContacts,
        conversations: conversationsByKey,
        ephemeralContactIDs: ephemeralContactIDs.map { $0.base64EncodedString() },
        myName: myName))
  }
}
