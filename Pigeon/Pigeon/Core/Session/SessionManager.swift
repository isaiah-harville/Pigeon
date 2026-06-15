//
//  SessionManager.swift
//  Pigeon
//
//  Orchestrates end-to-end-encrypted messaging with verified contacts over the
//  mesh: one SecureSession per contact, Noise handshakes routed through
//  SessionEnvelopes, and the binding check that ties the handshake to a
//  verified identity.
//

import Foundation
import PigeonCrypto
import PigeonMesh

/// Owns encrypted sessions with contacts and bridges them to the mesh.
///
/// Role assignment is deterministic so both ends agree without negotiation:
/// the device whose identity key sorts first is the Noise **initiator**, the
/// other is the **responder**. A periodic retry re-drives stalled handshakes,
/// since either device may add the contact (scan the QR) at a different moment.
@MainActor
@Observable
final class SessionManager {

    private let identity: IdentityManager
    private let mesh: MeshService

    private(set) var contacts: [Contact] = []
    /// Identity ids of contacts with a fully established, verified session.
    private(set) var establishedContactIDs: Set<Data> = []
    /// What the UI shows: every message this session, persisted or not.
    private(set) var conversations: [Data: [ChatMessage]] = [:]
    /// Contacts whose chat is ephemeral — new messages are kept in memory only.
    private(set) var ephemeralContactIDs: Set<Data> = []
    /// The local user's own display name, shared in their QR card.
    private(set) var myName: String = ""
    private(set) var log: [String] = []

    /// Called to surface a local notification when a message arrives while the
    /// app is backgrounded.
    var onIncomingNotification: (() -> Void)?
    /// A transient in-app banner shown when a message arrives in the foreground
    /// and the user isn't already viewing that chat.
    private(set) var banner: InAppBanner?
    /// The chat currently on screen (its notifications are suppressed while active).
    var activeChatID: Data?
    private var isAppActive = true
    /// Whether we've already posted the "you have messages, unlock" notification
    /// during the current locked session (reset on unlock).
    private var notifiedWhileLocked = false

    func setAppActive(_ active: Bool) { isAppActive = active }
    func dismissBanner() { banner = nil }

    struct InAppBanner: Equatable, Identifiable {
        let id = UUID()
        let title: String
        let body: String
    }

    private var sessions: [Data: SecureSession] = [:]
    /// The initiator's first handshake message, kept so retries resend the
    /// *same* message (stable ephemeral) rather than starting over.
    private var pendingMsg1: [Data: Data] = [:]
    /// Last handshake message received / sent per contact, for stop-and-wait
    /// retransmission (resend our reply when the peer repeats its message).
    private var lastHandshakeIn: [Data: Data] = [:]
    private var lastHandshakeOut: [Data: Data] = [:]
    /// The on-disk mirror of conversations (excludes ephemeral-era messages).
    private var persistedConversations: [Data: [ChatMessage]] = [:]
    private var retryTimer: Timer?

    private var myID: Data { identity.publicKey.rawRepresentation }

    /// Locked until the vault is unlocked with Face ID / Touch ID.
    private(set) var isUnlocked = false
    private var store: EncryptedStore?

    init(identity: IdentityManager, mesh: MeshService? = nil) {
        self.identity = identity
        self.mesh = mesh ?? MeshService()
        // Contacts/history load after the vault is unlocked; BLE runs regardless.
        self.mesh.onMessage = { [weak self] data in self?.handleInbound(data) }
        startRetryLoop()
    }

    /// Attaches the encrypted store after unlock: load persisted state and begin
    /// establishing sessions for known contacts.
    func attachStore(_ store: EncryptedStore) {
        self.store = store
        let state = store.load()
        contacts = state.contacts.compactMap { persisted in
            guard let bundle = try? IdentityBundle(decoding: persisted.bundle), bundle.isValid() else { return nil }
            return Contact(bundle: bundle, displayName: persisted.name)
        }
        var loaded: [Data: [ChatMessage]] = [:]
        for (key, messages) in state.conversations {
            if let id = Data(base64Encoded: key) { loaded[id] = messages }
        }
        persistedConversations = loaded
        conversations = loaded // start the in-memory view from what's on disk
        ephemeralContactIDs = Set(state.ephemeralContactIDs.compactMap { Data(base64Encoded: $0) })
        myName = state.myName
        isUnlocked = true
        notifiedWhileLocked = false
        for contact in contacts { ensureEstablishing(contactID: contact.id) }
    }

    /// Whether `contact`'s chat is in ephemeral (don't-persist-new-messages) mode.
    func isEphemeral(_ contact: Contact) -> Bool { ephemeralContactIDs.contains(contact.id) }

    /// Toggles ephemeral mode for one chat. Affects only future messages;
    /// already-saved history is left on disk untouched. The change is mirrored
    /// to the peer so both sides of the chat go ephemeral together.
    func setEphemeral(_ on: Bool, for contact: Contact) {
        applyEphemeral(on, for: contact.id, announce: true)
        sendEphemeralState(to: contact)
    }

    /// Applies an ephemeral change locally and adds a system notice in the chat.
    private func applyEphemeral(_ on: Bool, for contactID: Data, announce: Bool) {
        let changed = ephemeralContactIDs.contains(contactID) != on
        if on { ephemeralContactIDs.insert(contactID) } else { ephemeralContactIDs.remove(contactID) }
        if changed && announce {
            record(ChatMessage(mine: false, text: on ? "Ephemeral enabled" : "Ephemeral disabled", system: true),
                   for: contactID)
        }
        persist()
    }

    /// Sends our current ephemeral state for this chat to the peer (encrypted).
    private func sendEphemeralState(to contact: Contact) {
        guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id) else { return }
        let byte: UInt8 = ephemeralContactIDs.contains(contact.id) ? 1 : 0
        guard let ciphertext = try? session.encrypt(Data([0x01, byte])) else { return } // 0x01 = ephemeral cmd
        sendEnvelope(.control, payload: ciphertext, to: contact)
    }

    private func handleControl(_ payload: Data, from contact: Contact) {
        guard let session = sessions[contact.id],
              let plaintext = try? session.decrypt(payload),
              plaintext.count == 2, plaintext.first == 0x01 else { return }
        applyEphemeral(plaintext[plaintext.index(after: plaintext.startIndex)] == 1,
                       for: contact.id, announce: true)
    }

    // MARK: - UI passthroughs

    var status: PeerTransport.Status { mesh.status }
    var connectedPeerCount: Int { mesh.connectedPeerCount }
    var meshLog: [String] { mesh.log }

    /// Our own shareable identity bundle (for display as a QR code).
    var myBundle: IdentityBundle { identity.identityBundle }

    /// Our shareable card (identity bundle + our chosen display name) for the QR.
    var myCard: ContactCard { ContactCard(name: myName, bundle: identity.identityBundle) }

    /// Sets the local user's own display name (shared in their QR card).
    func setMyName(_ name: String) {
        myName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        persist()
    }

    /// Renames a contact locally (does not affect their card).
    func renameContact(_ contact: Contact, to name: String) {
        guard let index = contacts.firstIndex(where: { $0.id == contact.id }) else { return }
        contacts[index].displayName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        persist()
    }

    /// The safety number to compare in person with `contact`.
    func safetyNumber(with contact: Contact) -> String {
        guard let remote = try? IdentityPublicKey(rawRepresentation: contact.bundle.identityKey) else {
            return "—"
        }
        return SafetyNumber.compute(local: identity.publicKey, remote: remote)
    }

    // MARK: - Contacts

    /// Verifies and stores a scanned contact bundle, then begins establishing a session.
    @discardableResult
    func addContact(_ bundle: IdentityBundle, name: String) -> Bool {
        guard bundle.isValid() else {
            note("Rejected contact \"\(name)\": invalid identity binding")
            return false
        }
        guard bundle.identityKey != myID else {
            note("That QR is your own identity")
            return false
        }
        if let index = contacts.firstIndex(where: { $0.id == bundle.identityKey }) {
            // Refresh the full bundle (e.g. a rotated static key), not just the name.
            contacts[index] = Contact(bundle: bundle, displayName: name)
        } else {
            contacts.append(Contact(bundle: bundle, displayName: name))
        }
        persist()
        note("Added contact \"\(name)\"")
        // Re-scanning forces a fresh handshake (manual recovery if one stalled).
        resetSession(for: bundle.identityKey)
        establishIfNeeded(contactID: bundle.identityKey)
        return true
    }

    private func resetSession(for contactID: Data) {
        sessions[contactID] = nil
        pendingMsg1[contactID] = nil
        lastHandshakeIn[contactID] = nil
        lastHandshakeOut[contactID] = nil
        establishedContactIDs.remove(contactID)
    }

    // MARK: - Sending

    /// Sends `text` to `contact`. The message stays *pending* until the peer
    /// acknowledges it; it is (re)sent on each tick while a session exists and
    /// queued otherwise, so it is never silently dropped on a disconnect.
    func send(_ text: String, to contact: Contact) {
        let message = ChatMessage(mine: true, text: text, pending: true)
        record(message, for: contact.id)
        if establishedContactIDs.contains(contact.id) {
            transmit(message, to: contact)
        } else {
            note("Queued message for \"\(contact.displayName)\" (will send when connected)")
            ensureEstablishing(contactID: contact.id)
        }
    }

    /// Encrypts and sends one app message (id + text) over the session.
    private func transmit(_ message: ChatMessage, to contact: Contact) {
        guard let session = sessions[contact.id],
              let ciphertext = try? session.encrypt(Self.encodeMessage(id: message.id, text: message.text)) else { return }
        sendEnvelope(.message, payload: ciphertext, to: contact)
    }

    /// App message wire form (inside the ratchet): UUID string (36 bytes) ‖ text.
    private static func encodeMessage(id: UUID, text: String) -> Data {
        Data(id.uuidString.utf8) + Data(text.utf8)
    }

    private static func decodeMessage(_ data: Data) -> (id: UUID, text: String)? {
        guard data.count >= 36,
              let idString = String(data: data.prefix(36), encoding: .utf8),
              let id = UUID(uuidString: idString) else { return nil }
        return (id, String(decoding: data.dropFirst(36), as: UTF8.self))
    }

    /// Conversation history with `contact`.
    func messages(with contact: Contact) -> [ChatMessage] {
        conversations[contact.id] ?? []
    }

    /// The most recent non-system message with `contact`, for list previews.
    func lastMessage(with contact: Contact) -> ChatMessage? {
        conversations[contact.id]?.last(where: { !$0.system })
    }

    // MARK: - Inbound

    private func handleInbound(_ data: Data) {
        guard let envelope = try? SessionEnvelope(decoding: data) else { return }
        guard envelope.recipient == myID else { return } // not addressed to us
        guard let contact = contacts.first(where: { $0.id == envelope.sender }) else {
            // No matching contact. If we're locked (e.g. relaunched in the
            // background — no Face ID prompt possible), we can't decrypt or even
            // load contacts, but a message *is* for us: prompt the user to open
            // the app. Once, until unlocked, to avoid notification spam.
            if !isUnlocked && !notifiedWhileLocked {
                notifiedWhileLocked = true
                onIncomingNotification?()
            }
            return
        }
        switch envelope.type {
        case .handshake: handleHandshake(envelope.payload, from: contact)
        case .message: handleMessage(envelope.payload, from: contact)
        case .rehandshakeRequest: handleRehandshakeRequest(from: contact)
        case .ack: handleAck(envelope.payload, from: contact)
        case .control: handleControl(envelope.payload, from: contact)
        }
    }

    private func handleHandshake(_ payload: Data, from contact: Contact) {
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
            guard let session = sessions[contact.id] else { return } // not started; retry will
            guard (try? session.readHandshakeMessage(payload)) != nil else {
                return // unreadable reply — ignore, keep our session intact
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

    private func handleMessage(_ payload: Data, from contact: Contact) {
        guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id) else {
            // We have no session for a contact that's messaging us — our state is
            // stale (we likely restarted). Trigger reconnection.
            requestRehandshake(with: contact)
            return
        }
        guard let plaintext = try? session.decrypt(payload),
              let (id, text) = Self.decodeMessage(plaintext) else {
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
        record(received, for: contact.id)

        // Surface a notification unless the user is actively viewing this chat.
        guard !(isAppActive && activeChatID == contact.id) else { return }
        if isAppActive {
            showBanner(title: contact.displayName, body: text)
        } else {
            onIncomingNotification?() // local notification while backgrounded
        }
    }

    private func showBanner(title: String, body: String) {
        let banner = InAppBanner(title: title, body: body)
        self.banner = banner
        Task {
            try? await Task.sleep(for: .seconds(3))
            if self.banner == banner { self.banner = nil }
        }
    }

    private func sendAck(messageID: UUID, to contact: Contact) {
        guard let session = sessions[contact.id],
              let ciphertext = try? session.encrypt(Data(messageID.uuidString.utf8)) else { return }
        sendEnvelope(.ack, payload: ciphertext, to: contact)
    }

    private func handleAck(_ payload: Data, from contact: Contact) {
        guard let session = sessions[contact.id],
              let plaintext = try? session.decrypt(payload),
              let idString = String(data: plaintext, encoding: .utf8),
              let id = UUID(uuidString: idString) else { return }
        setPending(false, messageID: id, contactID: contact.id)
        persist()
    }

    /// Recovers a lost/stale session. The initiator restarts the handshake; the
    /// responder asks the initiator to do so.
    private func requestRehandshake(with contact: Contact) {
        if isInitiator(toward: contact.id) {
            resetSession(for: contact.id)
            establishIfNeeded(contactID: contact.id)
        } else {
            sendEnvelope(.rehandshakeRequest, payload: Data(), to: contact)
        }
    }

    private func handleRehandshakeRequest(from contact: Contact) {
        guard isInitiator(toward: contact.id) else { return } // only the initiator can start
        // Restart only if we're established (peer lost it) or never started; if a
        // handshake is already in progress, let it finish rather than clobber it.
        if establishedContactIDs.contains(contact.id) || sessions[contact.id] == nil {
            note("\"\(contact.displayName)\" requested re-handshake")
            resetSession(for: contact.id)
            establishIfNeeded(contactID: contact.id)
        }
    }

    // MARK: - Handshake driving

    private func isInitiator(toward contactID: Data) -> Bool {
        myID.lexicographicallyPrecedes(contactID)
    }

    private func establishIfNeeded(contactID: Data) {
        guard !establishedContactIDs.contains(contactID) else { return }
        guard isInitiator(toward: contactID),
              let contact = contacts.first(where: { $0.id == contactID }) else { return }

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

    private func makeResponder(for contact: Contact) -> SecureSession {
        let session = SecureSession.responder(localStatic: identity.noiseStaticKey)
        sessions[contact.id] = session
        return session
    }

    /// Sends any handshake messages this side currently owes, then finalizes.
    private func pump(_ session: SecureSession, with contact: Contact) {
        while !session.isEstablished {
            guard let message = try? session.writeHandshakeMessage() else { break }
            sendEnvelope(.handshake, payload: message, to: contact)
            lastHandshakeOut[contact.id] = message // for stop-and-wait retransmit
            note("→ handshake step to \"\(contact.displayName)\"")
        }
        finalize(session, with: contact)
    }

    /// Once Noise completes, verify the handshake's static key matches the
    /// verified contact bundle before trusting the channel.
    private func finalize(_ session: SecureSession, with contact: Contact) {
        guard session.isEstablished, !establishedContactIDs.contains(contact.id) else { return }
        guard let remoteStatic = session.remoteStaticKey,
              remoteStatic == contact.bundle.staticKey,
              contact.bundle.isValid() else {
            sessions[contact.id] = nil
            note("Session REJECTED with \"\(contact.displayName)\": static key does not match verified identity")
            return
        }
        establishedContactIDs.insert(contact.id)
        note("Secure session established with \"\(contact.displayName)\"")
        sendPending(to: contact) // deliver anything queued while out of range
        if ephemeralContactIDs.contains(contact.id) { sendEphemeralState(to: contact) } // re-sync ephemeral
    }

    private func sendEnvelope(_ type: EnvelopeType, payload: Data, to contact: Contact) {
        let envelope = SessionEnvelope(type: type, sender: myID, recipient: contact.id, payload: payload)
        mesh.send(envelope.encoded())
    }

    // MARK: - Retry

    private func startRetryLoop() {
        retryTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in self.tick() }
        }
    }

    private func tick() {
        for contact in contacts {
            if establishedContactIDs.contains(contact.id) {
                sendPending(to: contact) // retry unacked messages until they land
            } else {
                ensureEstablishing(contactID: contact.id)
            }
        }
    }

    /// Drives (re)establishment for one contact according to our role: the
    /// initiator (re)sends msg1; the responder nudges the initiator to start.
    private func ensureEstablishing(contactID: Data) {
        guard !establishedContactIDs.contains(contactID) else { return }
        if isInitiator(toward: contactID) {
            establishIfNeeded(contactID: contactID)
        } else if let contact = contacts.first(where: { $0.id == contactID }) {
            sendEnvelope(.rehandshakeRequest, payload: Data(), to: contact)
        }
    }

    // MARK: - Store-and-forward

    /// (Re)sends every unacknowledged outbound message for a contact. Pending is
    /// cleared only when the peer ACKs, so a message survives disconnects and
    /// lost packets; duplicates are deduplicated by the recipient.
    private func sendPending(to contact: Contact) {
        guard establishedContactIDs.contains(contact.id) else { return }
        let pending = (conversations[contact.id] ?? []).filter { $0.mine && $0.pending }
        for message in pending {
            transmit(message, to: contact)
        }
    }

    /// Flips a message's pending flag in both the in-memory view and the disk mirror.
    private func setPending(_ pending: Bool, messageID: UUID, contactID: Data) {
        if let index = conversations[contactID]?.firstIndex(where: { $0.id == messageID }) {
            conversations[contactID]?[index].pending = pending
        }
        if let index = persistedConversations[contactID]?.firstIndex(where: { $0.id == messageID }) {
            persistedConversations[contactID]?[index].pending = pending
        }
    }

    // MARK: - Logging & persistence

    private func note(_ message: String) {
        log.append(message)
        if log.count > 200 { log.removeFirst(log.count - 200) }
    }

    /// Appends a message to the in-memory view, and to the on-disk mirror unless
    /// the chat is ephemeral, then persists.
    private func record(_ message: ChatMessage, for contactID: Data) {
        conversations[contactID, default: []].append(message)
        if !ephemeralContactIDs.contains(contactID) {
            persistedConversations[contactID, default: []].append(message)
        }
        persist()
    }

    /// Writes contacts, the on-disk conversation mirror, and ephemeral flags to
    /// the encrypted store (no-op before unlock).
    private func persist() {
        guard let store, isUnlocked else { return }
        let persistedContacts = contacts.map {
            PersistedContact(name: $0.displayName, bundle: $0.bundle.encoded())
        }
        var conversationsByKey: [String: [ChatMessage]] = [:]
        for (id, messages) in persistedConversations {
            conversationsByKey[id.base64EncodedString()] = messages
        }
        store.save(PersistedState(contacts: persistedContacts,
                                  conversations: conversationsByKey,
                                  ephemeralContactIDs: ephemeralContactIDs.map { $0.base64EncodedString() },
                                  myName: myName))
    }
}
