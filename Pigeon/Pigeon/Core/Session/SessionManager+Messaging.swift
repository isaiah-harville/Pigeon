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
    case .x3dhInit: handleX3DHInit(envelope.payload, from: contact)
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

  /// Responder side of async first contact: a peer opened a session against our
  /// published prekeys (we may have been offline when they sent it). Reconstruct
  /// the session, then process the `message` envelopes that follow normally.
  func handleX3DHInit(_ payload: Data, from contact: Contact) {
    // Only the lexicographic responder accepts initiations; if we're the
    // initiator we drive our own session and ignore a crossed initiation.
    guard !isInitiator(toward: contact.id) else { return }

    // A retransmit of the initiation we already processed: ignore. Re-running
    // `X3DH.respond` would reset an advanced ratchet and break decryption. A
    // *different* header means the peer restarted — fall through and rebuild.
    if payload == lastX3DHIn[contact.id] { return }

    guard let header = try? X3DHInitiation(decoding: payload) else { return }
    // Binding check: the initiation's identity must match the verified contact
    // (constant-time over public keys, mirroring the Noise `finalize` check).
    guard ConstantTime.equals(header.initiatorIdentity.staticKey, contact.bundle.staticKey),
      contact.bundle.isValid()
    else {
      note(sessionRejectedMessage(for: contact))
      return
    }
    // Look up the private signed prekey the initiator named.
    guard let signedPrekey = identity.signedPrekey(forID: header.signedPrekeyID) else {
      note("X3DH init from \"\(contact.displayName)\" referenced an unknown prekey")
      return
    }
    // We publish SPK-only in the QR (no one-time prekeys), so a header should
    // carry none; if a future bundle did, we have no OPK store to satisfy it and
    // `respond` will reject — surfaced as a failure rather than silently wrong.
    let oneTimePrekey: DHKeyPair? = nil
    guard
      let session = try? X3DH.respond(
        localStatic: identity.noiseStaticKey,
        signedPrekey: signedPrekey,
        oneTimePrekey: oneTimePrekey,
        header: header)
    else {
      note("X3DH respond failed from \"\(contact.displayName)\"")
      return
    }
    lastX3DHIn[contact.id] = payload
    sessions[contact.id] = session
    establishedContactIDs.insert(contact.id)
    note("Secure session established with \"\(contact.displayName)\" (async first contact)")
  }

  func handleMessage(_ payload: Data, from contact: Contact, channel: TransportChannel) {
    guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id) else {
      // We have no session for a contact that's messaging us — our state is
      // stale (we likely restarted). Trigger reconnection.
      requestRehandshake(with: contact)
      return
    }
    guard let plaintext = try? session.decrypt(payload),
      var received = Self.decodeMessage(plaintext)
    else {
      note("Decrypt failed from \"\(contact.displayName)\" — re-establishing")
      requestRehandshake(with: contact)
      return
    }
    // Acknowledge every delivery (even duplicates) so the sender stops retrying.
    sendAck(messageID: received.id, to: contact)
    // Deduplicate by the sender's message id (a retried message arrives twice).
    if conversations[contact.id]?.contains(where: { $0.id == received.id }) == true { return }
    received.transport = channel
    record(received, for: contact.id)

    // Surface a notification unless the user is actively viewing this chat.
    guard !(isAppActive && activeChatID == contact.id) else { return }
    if isAppActive {
      showBanner(title: contact.displayName, body: received.text)
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
    // An ack proves the peer holds the session, so the X3DH initiation has
    // landed — stop resending it.
    pendingX3DHInit[contact.id] = nil
    setPending(false, messageID: id, contactID: contact.id)
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
  }

  /// Sends our current transport choice for this chat to the peer (encrypted).
  func sendTransportState(to contact: Contact) {
    guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id) else {
      return
    }
    let byte: UInt8 = bluetoothChatIDs.contains(contact.id) ? 1 : 0
    let command = Data([0x02, byte])  // 0x02 = transport cmd (1 = Bluetooth, 0 = relay)
    guard let ciphertext = try? session.encrypt(command) else { return }
    sendEnvelope(.control, payload: ciphertext, to: contact)
  }

  func handleControl(_ payload: Data, from contact: Contact) {
    guard let session = sessions[contact.id],
      let plaintext = try? session.decrypt(payload),
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

    // Prefer async X3DH first contact when we hold the peer's prekey bundle: it
    // establishes immediately and reaches the peer even if they're offline now
    // (they drain it from their relay mailbox later). Falls back to the
    // interactive Noise handshake for legacy contacts without prekeys.
    if contact.prekeyBundle != nil {
      establishViaX3DH(contact)
      return
    }

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

  /// Initiator side of async first contact. Builds the session from the peer's
  /// published prekeys, marks it established immediately (the binding is checked
  /// here), and emits the initiation header. Any queued messages are delivered
  /// right after, so they land in the peer's mailbox whether or not they're
  /// online. The header is retained (`pendingX3DHInit`) and resent until the
  /// peer acknowledges, surviving loss and a peer that's offline for a while.
  func establishViaX3DH(_ contact: Contact) {
    guard let peerBundle = contact.prekeyBundle else { return }
    // Defense-in-depth binding check (the card scanner already verified it):
    // the prekey bundle's identity static key must equal the verified contact.
    guard ConstantTime.equals(peerBundle.identity.staticKey, contact.bundle.staticKey) else {
      note(sessionRejectedMessage(for: contact))
      return
    }
    guard
      let initiation = try? X3DH.initiate(
        localStatic: identity.noiseStaticKey,
        localIdentity: identity.identityBundle,
        bundle: peerBundle)
    else {
      note("X3DH first contact failed with \"\(contact.displayName)\"")
      return
    }
    sessions[contact.id] = initiation.session
    let header = initiation.header.encoded()
    pendingX3DHInit[contact.id] = header
    establishedContactIDs.insert(contact.id)
    sendEnvelope(.x3dhInit, payload: header, to: contact)
    note("→ X3DH first contact to \"\(contact.displayName)\"")
    sendPending(to: contact)  // deliver anything queued (header precedes it)
    if ephemeralContactIDs.contains(contact.id) { sendEphemeralState(to: contact) }
    if bluetoothChatIDs.contains(contact.id) { sendTransportState(to: contact) }
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
    if bluetoothChatIDs.contains(contact.id) { sendTransportState(to: contact) }  // re-sync link choice
  }

  func sendEnvelope(_ type: EnvelopeType, payload: Data, to contact: Contact) {
    let envelope = SessionEnvelope(
      type: type, sender: myID, recipient: contact.id, payload: payload)
    // App messages travel over the chat's chosen link (relay by default). Every
    // other envelope — handshakes, acks, the control message that *syncs* the
    // link choice — floods both links so establishment and state sync stay
    // robust regardless of the selected transport (#24). The recipient hint lets
    // the relay address this contact's mailbox directly; BLE ignores it.
    let channels: Set<TransportKind> =
      type == .message ? chatChannels(for: contact) : TransportKind.all
    mesh.send(envelope.encoded(), to: contact.id, over: channels)
  }

  func sessionRejectedMessage(for contact: Contact) -> String {
    """
    Session REJECTED with "\(contact.displayName)": static key does not match \
    verified identity
    """
  }

}
