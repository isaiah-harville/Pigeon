import CryptoKit
import Foundation
import PigeonFFI

extension SessionManager {
  func canUseCorePairwise(with contact: Contact) -> Bool {
    coreClient != nil && contact.pairwiseControlPrekeyBundle != nil
  }

  func transmitDirectCore(_ message: ChatMessage, to contact: Contact) -> Bool {
    let body: PigeonDirectApplication.Body
    switch message.event {
    case .screenshot: body = .screenshotNotice
    case .contactAccepted: body = .contactAcceptance
    case .relayRecommendation:
      body = .relayRecommendation(urls: message.relayRecommendationURLs)
    case nil:
      body = .message(
        PigeonDirectMessage(
          text: message.text,
          senderTimestampMilliseconds: Int64(message.date.timeIntervalSince1970 * 1_000),
          replySnippet: message.replySnippet))
    }
    do {
      try sendDirectCoreApplication(body, id: message.id, to: contact)
      return true
    } catch {
      return false
    }
  }

  func absorbDirectCoreEvent(_ event: PigeonDirectApplicationReceivedEvent) throws {
    let contact = try contactForDirectCoreEvent(event)
    if try applyDirectCoreApplication(event.application, from: contact) {
      try enqueueDirectAcknowledgement(messageID: event.application.id, to: contact)
    }
  }

  private func contactForDirectCoreEvent(
    _ event: PigeonDirectApplicationReceivedEvent
  ) throws -> Contact {
    if let index = contacts.firstIndex(where: { $0.id == event.senderIdentity }) {
      if contacts[index].pairwiseControlPrekeyBundle == nil,
        !event.senderContactCard.isEmpty
      {
        guard let card = ContactCard(scanned: event.senderContactCard.base64EncodedString()),
          card.bundle.identityKey == event.senderIdentity,
          let controlPrekey = card.pairwiseControlPrekeyBundle
        else { throw PlatformError.InvalidOutput }
        contacts[index].pairwiseControlPrekeyBundle = controlPrekey
      }
      return contacts[index]
    }
    guard !blockedContactIDs.contains(event.senderIdentity),
      stagedIncomingRequestCount < Self.maximumIncomingRequests,
      !event.senderContactCard.isEmpty,
      let card = ContactCard(scanned: event.senderContactCard.base64EncodedString()),
      card.bundle.identityKey == event.senderIdentity,
      let controlPrekey = card.pairwiseControlPrekeyBundle
    else { throw PlatformError.InvalidOutput }
    let sanitized = DisplayName.sanitize(card.name)
    let contact = Contact(
      bundle: card.bundle,
      displayName: sanitized.isEmpty ? "Unnamed" : sanitized,
      relayURLs: card.relayURLs,
      prekeyBundle: card.prekeyBundle,
      pairwiseControlPrekeyBundle: controlPrekey,
      verifiedInPerson: false,
      requestState: .incoming,
      requestCreatedAt: Date())
    contacts.append(contact)
    return contact
  }

  private func applyDirectCoreApplication(
    _ application: PigeonDirectApplication, from contact: Contact
  ) throws -> Bool {
    switch application.body {
    case .message(let value):
      try absorbDirectMessage(value, applicationID: application.id, from: contact)
      return true
    case .acknowledgement(let messageID):
      try absorbDirectAcknowledgement(messageID, from: contact)
      return false
    case .reaction(let messageID, let emoji):
      try absorbDirectReaction(messageID: messageID, emoji: emoji, from: contact)
      return true
    case .ephemeralState(let enabled):
      try absorbDirectEphemeralState(enabled, from: contact)
      return true
    case .transportState(let mode):
      try absorbDirectTransportState(mode, from: contact)
      return true
    case .screenshotNotice, .contactAcceptance, .relayRecommendation:
      try absorbDirectSystemApplication(application, from: contact)
      return true
    }
  }

  private func absorbDirectSystemApplication(
    _ application: PigeonDirectApplication, from contact: Contact
  ) throws {
    let text: String
    let kind: ChatSystemEvent
    let relayURLs: [String]
    switch application.body {
    case .screenshotNotice:
      text = Self.screenshotNotice(mine: false, contactName: contact.displayName)
      kind = .screenshot
      relayURLs = []
    case .contactAcceptance:
      acceptOutgoingRequest(from: contact.id)
      text = "Message request accepted"
      kind = .contactAccepted
      relayURLs = []
    case .relayRecommendation(let urls):
      text = "\(contact.displayName) shared a relay"
      kind = .relayRecommendation
      relayURLs = RelaySettings.sanitizeSharedRelayURLs(urls)
    default:
      throw PlatformError.InvalidOutput
    }
    try recordDirectSystemEvent(
      applicationID: application.id, text: text, kind: kind,
      relayURLs: relayURLs, from: contact)
  }

  @discardableResult
  func sendDirectCoreApplication(
    _ body: PigeonDirectApplication.Body,
    id: UUID,
    to contact: Contact
  ) throws -> PigeonCoreOutput {
    guard let current = contacts.first(where: { $0.id == contact.id }) else {
      throw PlatformError.Unavailable
    }
    let senderContactCard: Data
    if current.requestState == .outgoing, case .message = body {
      guard let encoded = myCard?.encoded(), let bytes = Data(base64Encoded: encoded) else {
        throw PlatformError.Unavailable
      }
      senderContactCard = bytes
    } else {
      senderContactCard = Data()
    }
    return try executeCore(
      PigeonCoreCommand(
        id: "send-direct:\(id.uuidString.lowercased())",
        body: .sendDirectApplication(
          PigeonSendDirectApplication(
            recipientIdentity: current.id,
            application: PigeonDirectApplication(id: id.uuidString, body: body),
            localOnly: usesBluetooth(current) || relay == nil,
            senderContactCard: senderContactCard))))
  }

  private func absorbDirectAcknowledgement(_ messageID: String, from contact: Contact) throws {
    guard let id = UUID(uuidString: messageID) else { return }
    conversationStore.setDelivery(.delivered, messageID: id, contactID: contact.id)
    guard persist() else { throw PlatformError.Unavailable }
  }

  private func absorbDirectReaction(
    messageID: String, emoji: String?, from contact: Contact
  ) throws {
    guard let id = UUID(uuidString: messageID) else { return }
    applyReaction(emoji.map { String($0.prefix(8)) }, messageID: id, from: contact)
    guard isPersistenceHealthy else { throw PlatformError.Unavailable }
  }

  private func absorbDirectEphemeralState(_ enabled: Bool, from contact: Contact) throws {
    guard contact.requestState == .none else { return }
    applyEphemeral(enabled, for: contact.id, announce: true)
    guard isPersistenceHealthy else { throw PlatformError.Unavailable }
  }

  private func absorbDirectTransportState(
    _ mode: PigeonDirectTransportMode, from contact: Contact
  ) throws {
    guard contact.requestState == .none else { return }
    switch mode {
    case .relay: applyTransport(useBluetooth: false, for: contact.id, announce: true)
    case .local: applyTransport(useBluetooth: true, for: contact.id, announce: true)
    case .unknown: throw PlatformError.InvalidOutput
    }
    guard isPersistenceHealthy else { throw PlatformError.Unavailable }
  }

  private func absorbDirectMessage(
    _ value: PigeonDirectMessage,
    applicationID: String,
    from contact: Contact
  ) throws {
    let id = directHistoryID(applicationID: applicationID, senderIdentity: contact.id)
    if !conversationStore.contains(messageID: id, for: contact.id) {
      if contact.requestState == .incoming,
        let index = contacts.firstIndex(where: { $0.id == contact.id })
      {
        contacts[index].introductionReceived = true
      }
      var message = ChatMessage(mine: false, text: value.text)
      message.id = id
      message.replySnippet = value.replySnippet.map(Self.clampSnippet)
      let sentAt = Date(timeIntervalSince1970: Double(value.senderTimestampMilliseconds) / 1_000)
      message.sentAt = min(sentAt, message.date)
      guard record(message, for: contact.id) else { throw PlatformError.Unavailable }
      presenter.notifyIncoming(
        contactID: contact.id,
        title: contact.requestState == .incoming ? "Message Request" : contact.displayName,
        body: contact.requestState == .incoming ? "New message request" : message.text)
    }
  }

  private func recordDirectSystemEvent(
    applicationID: String,
    text: String,
    kind: ChatSystemEvent,
    relayURLs: [String],
    from contact: Contact
  ) throws {
    let id = directHistoryID(applicationID: applicationID, senderIdentity: contact.id)
    guard !conversationStore.contains(messageID: id, for: contact.id) else { return }
    var message = ChatMessage(mine: false, text: text, system: true)
    message.id = id
    message.event = kind
    message.relayRecommendationURLs = relayURLs
    guard record(message, for: contact.id) else { throw PlatformError.Unavailable }
  }

  private func enqueueDirectAcknowledgement(messageID: String, to contact: Contact) throws {
    guard let coreClient else { throw PlatformError.Unavailable }
    let id = UUID()
    _ = try coreClient.execute(
      PigeonCoreCommand(
        id: "send-direct-ack:\(id.uuidString.lowercased())",
        body: .sendDirectApplication(
          PigeonSendDirectApplication(
            recipientIdentity: contact.id,
            application: PigeonDirectApplication(
              id: id.uuidString,
              body: .acknowledgement(messageID: messageID)),
            localOnly: usesBluetooth(contact) || relay == nil))))
    let snapshot = try coreClient.stateSnapshot()
    applyCoreSnapshot(snapshot)
    fanOutPairwiseMesh(snapshot: snapshot)
    if relay != nil {
      pairwiseRelay.reconfigure(snapshot: snapshot)
    }
  }

  private func directHistoryID(applicationID: String, senderIdentity: Data) -> UUID {
    if let id = UUID(uuidString: applicationID) { return id }
    var transcript = Data("pigeon.direct-history-id.v1\0".utf8)
    transcript.append(senderIdentity)
    transcript.append(Data(applicationID.utf8))
    var bytes = Array(SHA256.hash(data: transcript).prefix(16))
    bytes[6] = (bytes[6] & 0x0F) | 0x50
    bytes[8] = (bytes[8] & 0x3F) | 0x80
    return UUID(
      uuid: (
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
      ))
  }
}
