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
    /// Decrypted conversation history per contact (in-memory, this session).
    private(set) var conversations: [Data: [ChatMessage]] = [:]
    private(set) var log: [String] = []

    private var sessions: [Data: SecureSession] = [:]
    private var retryTimer: Timer?

    private var myID: Data { identity.publicKey.rawRepresentation }

    init(identity: IdentityManager, mesh: MeshService? = nil) {
        self.identity = identity
        self.mesh = mesh ?? MeshService()
        self.contacts = Self.loadContacts()
        self.mesh.onMessage = { [weak self] data in self?.handleInbound(data) }
        startRetryLoop()
    }

    // MARK: - UI passthroughs

    var status: PeerTransport.Status { mesh.status }
    var connectedPeerCount: Int { mesh.connectedPeerCount }
    var meshLog: [String] { mesh.log }

    /// Our own shareable identity bundle (for display as a QR code).
    var myBundle: IdentityBundle { identity.identityBundle }

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
            contacts[index].displayName = name
        } else {
            contacts.append(Contact(bundle: bundle, displayName: name))
        }
        Self.saveContacts(contacts)
        note("Added contact \"\(name)\"")
        establishIfNeeded(contactID: bundle.identityKey)
        return true
    }

    // MARK: - Sending

    /// Encrypts and sends `text` to `contact` over its established session.
    func send(_ text: String, to contact: Contact) {
        guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id) else {
            note("No secure session with \"\(contact.displayName)\" yet")
            establishIfNeeded(contactID: contact.id)
            return
        }
        do {
            let ciphertext = try session.encrypt(Data(text.utf8))
            sendEnvelope(.message, payload: ciphertext, to: contact)
            conversations[contact.id, default: []].append(ChatMessage(mine: true, text: text))
        } catch {
            note("Encrypt failed: \(error)")
        }
    }

    /// Conversation history with `contact`.
    func messages(with contact: Contact) -> [ChatMessage] {
        conversations[contact.id] ?? []
    }

    // MARK: - Inbound

    private func handleInbound(_ data: Data) {
        guard let envelope = try? SessionEnvelope(decoding: data) else { return }
        guard envelope.recipient == myID else { return } // not addressed to us
        guard let contact = contacts.first(where: { $0.id == envelope.sender }) else {
            return // message from someone we have not verified
        }
        switch envelope.type {
        case .handshake: handleHandshake(envelope.payload, from: contact)
        case .message: handleMessage(envelope.payload, from: contact)
        }
    }

    private func handleHandshake(_ payload: Data, from contact: Contact) {
        // An inbound handshake means the peer is driving; if we have no session
        // (or our in-progress one no longer fits), (re)start as responder.
        var session = sessions[contact.id] ?? makeResponder(for: contact)
        do {
            try session.readHandshakeMessage(payload)
        } catch {
            // Likely a fresh restart from the initiator: reset and try once more.
            session = makeResponder(for: contact)
            guard (try? session.readHandshakeMessage(payload)) != nil else {
                note("Handshake read failed with \"\(contact.displayName)\"")
                return
            }
        }
        pump(session, with: contact)
    }

    private func handleMessage(_ payload: Data, from contact: Contact) {
        guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id) else { return }
        do {
            let plaintext = try session.decrypt(payload)
            let text = String(decoding: plaintext, as: UTF8.self)
            conversations[contact.id, default: []].append(ChatMessage(mine: false, text: text))
        } catch {
            note("Decrypt failed from \"\(contact.displayName)\"")
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
        // (Re)start a fresh initiator handshake.
        let session = SecureSession.initiator(localStatic: identity.noiseStaticKey)
        sessions[contactID] = session
        pump(session, with: contact)
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
            note("⚠️ Session REJECTED with \"\(contact.displayName)\": static key does not match verified identity")
            return
        }
        establishedContactIDs.insert(contact.id)
        note("🔒 Secure session established with \"\(contact.displayName)\"")
    }

    private func sendEnvelope(_ type: EnvelopeType, payload: Data, to contact: Contact) {
        let envelope = SessionEnvelope(type: type, sender: myID, recipient: contact.id, payload: payload)
        mesh.send(envelope.encoded())
    }

    // MARK: - Retry

    private func startRetryLoop() {
        retryTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in self.retryUnestablished() }
        }
    }

    private func retryUnestablished() {
        for contact in contacts where !establishedContactIDs.contains(contact.id) {
            establishIfNeeded(contactID: contact.id)
        }
    }

    // MARK: - Logging & persistence

    private func note(_ message: String) {
        log.append(message)
        if log.count > 200 { log.removeFirst(log.count - 200) }
    }

    private static let contactsKey = "pigeon.contacts"

    private static func saveContacts(_ contacts: [Contact]) {
        // Public keys only; not sensitive. Moves to the encrypted store in Phase 5.
        let array = contacts.map { ["name": $0.displayName, "bundle": $0.bundle.encoded().base64EncodedString()] }
        UserDefaults.standard.set(array, forKey: contactsKey)
    }

    private static func loadContacts() -> [Contact] {
        guard let array = UserDefaults.standard.array(forKey: contactsKey) as? [[String: String]] else { return [] }
        return array.compactMap { entry in
            guard let name = entry["name"], let b64 = entry["bundle"],
                  let data = Data(base64Encoded: b64),
                  let bundle = try? IdentityBundle(decoding: data), bundle.isValid() else { return nil }
            return Contact(bundle: bundle, displayName: name)
        }
    }
}
