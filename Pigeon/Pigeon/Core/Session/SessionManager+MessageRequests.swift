import Foundation

extension SessionManager {
  static var maximumIncomingRequests: Int { 50 }
  static var preIntroductionLifetime: TimeInterval { 10 * 60 }
  static var incomingRequestLifetime: TimeInterval { 7 * 24 * 3600 }

  static func canAdmitIncomingRequest(existingDates: [Date], now: Date) -> Bool {
    _ = now
    return existingDates.count < maximumIncomingRequests
  }

  var stagedIncomingRequestCount: Int {
    contacts.count { $0.requestState == .incoming && !$0.introductionReceived }
  }

  /// Converts a freshly scanned, one-sided contact into the existing
  /// one-introduction request flow. In-person verification is directional: the
  /// scanner has authenticated this contact, but the recipient has not yet
  /// authenticated the scanner.
  @discardableResult
  func beginMessageRequest(to contactID: Data) -> Bool {
    guard let index = contacts.firstIndex(where: { $0.id == contactID }),
      contacts[index].requestState == .none,
      !contacts[index].introductionSent,
      !contacts[index].introductionReceived,
      conversationStore.messages(for: contactID).isEmpty
    else { return false }
    contacts[index].requestState = .outgoing
    guard persist() else {
      contacts[index].requestState = .none
      return false
    }
    return true
  }

  @discardableResult
  func purgeExpiredIncomingRequests(now: Date) -> Bool {
    let expiredIDs = contacts.compactMap { contact -> Data? in
      guard contact.requestState == .incoming else { return nil }
      let lifetime =
        contact.introductionReceived
        ? Self.incomingRequestLifetime : Self.preIntroductionLifetime
      guard let createdAt = contact.requestCreatedAt,
        createdAt >= now.addingTimeInterval(-lifetime)
      else { return contact.id }
      return nil
    }
    guard !expiredIDs.isEmpty else { return true }
    removeIncomingRequests(ids: expiredIDs)
    return persist()
  }

  func clearStagedIncomingRequests() {
    let stagedIDs = contacts.compactMap { contact -> Data? in
      contact.requestState == .incoming && !contact.introductionReceived ? contact.id : nil
    }
    guard !stagedIDs.isEmpty else { return }
    removeIncomingRequests(ids: stagedIDs)
    persist()
  }

  private func removeIncomingRequests(ids: [Data]) {
    let idSet = Set(ids)
    for id in ids {
      conversationStore.clear(contactID: id)
      activeConversationIDs.remove(id)
      ephemeralContactIDs.remove(id)
      bluetoothChatIDs.remove(id)
      resetSession(for: id)
      rehandshakeGate.clear(id)
    }
    contacts.removeAll { idSet.contains($0.id) }
  }

  /// Sends an authenticated relay recommendation inside an accepted chat. The
  /// receiver still probes and explicitly adds it; this never changes settings.
  func shareRelay(_ url: URL, with contact: Contact) {
    guard let current = contacts.first(where: { $0.id == contact.id }),
      current.requestState == .none,
      relayURLs.contains(url),
      RelaySettings.sanitizeSharedRelayURLs([url.absoluteString]) == [url.absoluteString]
    else { return }
    var event = ChatMessage(mine: true, text: "You shared a relay", pending: true)
    event.system = true
    event.event = .relayRecommendation
    event.relayRecommendationURLs = [url.absoluteString]
    event.transientOutbox = isEphemeral(current)
    guard record(event, for: contact.id) else { return }
    armDeliveryDeadline(messageID: event.id, contactID: contact.id)
    if establishedContactIDs.contains(contact.id) {
      transmit(event, to: current)
    } else {
      ensureEstablishing(contactID: contact.id)
    }
  }
}
