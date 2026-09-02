import CryptoKit
import Foundation
import PigeonFFI

extension SessionManager {
  static let maximumGroupMembers = 128
  static let maximumGroupMessageBytes = 64 * 1024

  enum GroupCreationError: Error, Equatable {
    case invalidName
    case invalidRoster
    case invalidRelay
    case unreachableMember
    case invalidCoordinatorKey
  }

  enum GroupMessagingError: Error, Equatable {
    case invalidMessage
    case inactiveGroup
  }

  @discardableResult
  func createGroup(
    name: String,
    memberIDs: Set<Data>,
    relayURL: URL,
    meshEnabled: Bool
  ) async throws -> PigeonCoreOutput {
    guard Self.isValidGroupName(name) else { throw GroupCreationError.invalidName }
    guard (2..<Self.maximumGroupMembers).contains(memberIDs.count),
      !memberIDs.contains(myID)
    else { throw GroupCreationError.invalidRoster }
    guard let scheme = relayURL.scheme?.lowercased(),
      scheme == "https" || scheme == "wss",
      GroupRelayTransport.endpoint(for: relayURL) != nil
    else { throw GroupCreationError.invalidRelay }

    let selected = memberIDs.compactMap { memberID in
      contacts.first { $0.id == memberID && $0.requestState == .none }
    }
    guard selected.count == memberIDs.count,
      selected.allSatisfy({ contact in
        contact.pairwiseControlPrekeyBundle != nil
          && (contact.preferredRelayURL != nil || !contact.relayURLs.isEmpty)
      })
    else { throw GroupCreationError.unreachableMember }

    let coordinatorKey = try await resolveGroupCoordinatorKey(relayURL)
    guard coordinatorKey.count == 32,
      (try? Curve25519.Signing.PublicKey(rawRepresentation: coordinatorKey)) != nil
    else { throw GroupCreationError.invalidCoordinatorKey }
    return try executeCore(
      PigeonCoreCommand(
        id: "create-group:\(UUID().uuidString.lowercased())",
        body: .createGroup(
          PigeonCreateGroup(
            name: name,
            memberIdentities: memberIDs.sorted { $0.lexicographicallyPrecedes($1) },
            relayURL: relayURL.absoluteString,
            meshEnabled: meshEnabled,
            coordinatorPublicKey: coordinatorKey))))
  }

  @discardableResult
  func sendGroupMessage(
    _ text: String,
    in group: PigeonGroupState,
    replyToMessageID: String?
  ) throws -> PigeonCoreOutput {
    let body = Data(text.utf8)
    guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      !body.isEmpty, body.count <= Self.maximumGroupMessageBytes
    else { throw GroupMessagingError.invalidMessage }
    guard !group.dissolved, group.memberIdentities.contains(myID) else {
      throw GroupMessagingError.inactiveGroup
    }
    let commandID = "send-group-message:\(UUID().uuidString.lowercased())"
    return try executeCore(
      PigeonCoreCommand(
        id: commandID,
        body: .sendGroupMessage(
          PigeonSendGroupMessage(
            groupID: group.groupID,
            messageID: commandID,
            body: body,
            senderTimestampMilliseconds: Int64(Date().timeIntervalSince1970 * 1_000),
            replyToMessageID: replyToMessageID))))
  }

  @discardableResult
  func changeGroupPolicy(
    _ kind: PigeonGroupPolicyChangeKind,
    in group: PigeonGroupState,
    subjectIdentity: Data,
    stringValue: String,
    boolValue: Bool
  ) throws -> PigeonCoreOutput {
    if kind == .nameChanged, !Self.isValidGroupName(stringValue) {
      throw GroupCreationError.invalidName
    }
    guard !group.dissolved else { throw GroupMessagingError.inactiveGroup }
    return try executeCore(
      PigeonCoreCommand(
        id: "change-group-policy:\(UUID().uuidString.lowercased())",
        body: .changeGroupPolicy(
          PigeonChangeGroupPolicy(
            groupID: group.groupID,
            kind: kind,
            subjectIdentity: subjectIdentity,
            stringValue: stringValue,
            boolValue: boolValue))))
  }

  private static func isValidGroupName(_ name: String) -> Bool {
    name.precomposedStringWithCanonicalMapping == name
      && name == name.trimmingCharacters(in: .whitespacesAndNewlines)
      && !name.isEmpty
      && !name.contains("  ")
      && name.unicodeScalars.count <= 64
      && name.utf8.count <= 256
  }

  func makePairwiseRelay() -> PairwiseRelayTransport {
    let transport = PairwiseRelayTransport(sender: myID)
    transport.onEffectDelivered = { [weak self] itemID in
      self?.acknowledgeCoreOutbound(itemID) ?? false
    }
    return transport
  }

  func registerPairwiseContacts() throws {
    for contact in contacts {
      try registerPairwiseContactIfAvailable(contact)
    }
  }

  func registerPairwiseContactIfAvailable(_ contact: Contact) throws {
    guard let prekey = contact.pairwiseControlPrekeyBundle,
      let relayURL = contact.preferredRelayURL ?? contact.relayURLs.first
    else { return }
    let transcript = contact.id + prekey.encoded + Data(relayURL.absoluteString.utf8)
    let commandID = SHA256.hash(data: transcript)
      .map { String(format: "%02x", $0) }
      .joined()
    try executeCore(
      PigeonCoreCommand(
        id: "register-pairwise-contact:\(commandID)",
        body: .registerPairwiseContact(
          PigeonRegisterPairwiseContact(
            prekeyBundle: prekey.encoded,
            relayURL: relayURL.absoluteString))))
  }

  func makeGroupRelay() -> GroupRelayTransport {
    let transport = GroupRelayTransport { [weak self] groupID, nonce in
      guard let coreClient = self?.coreClient else {
        throw PlatformError.Unavailable
      }
      return try coreClient.relayChallengeSignature(groupID: groupID, nonce: nonce)
    }
    transport.onMessage = { [weak self] ciphertext, requestID in
      self?.consumeGroupRelayMessage(ciphertext, requestID: requestID) ?? false
    }
    transport.onCoordinatorCandidate = { [weak self] receipt, candidate, requestID in
      self?.consumeCoordinatorCandidate(
        receipt,
        candidate: candidate,
        requestID: requestID) ?? false
    }
    transport.onEffectDelivered = { [weak self] itemID in
      self?.acknowledgeCoreOutbound(itemID) ?? false
    }
    return transport
  }

  /// Atomically replaces the host projection with a snapshot from the durable
  /// core. A stale asynchronous result cannot roll the UI back.
  func applyCoreSnapshot(_ snapshot: PigeonCoreSnapshot) {
    guard snapshot.checkpointGeneration >= coreSnapshotGeneration else { return }
    groups = snapshot.groups
    coreSnapshotGeneration = snapshot.checkpointGeneration
  }

  /// Runs one idempotent core command and refreshes every host projection from
  /// the checkpoint that the core persisted before returning its effects.
  @discardableResult
  func executeCore(_ command: PigeonCoreCommand) throws -> PigeonCoreOutput {
    guard let coreClient else { throw PlatformError.Unavailable }
    let output = try coreClient.execute(command)
    let snapshot = try coreClient.stateSnapshot()
    guard snapshot.checkpointGeneration == output.checkpointGeneration else {
      throw PlatformError.InvalidOutput
    }
    applyCoreSnapshot(snapshot)
    try absorbCoreEvents(snapshot.pendingEvents)
    let refreshed = try coreClient.stateSnapshot()
    groupRelay.reconfigure(snapshot: refreshed)
    if relay != nil { pairwiseRelay.reconfigure(snapshot: refreshed) }
    return output
  }

  /// Reduces replayable core events into encrypted app history, saves that
  /// history, and only then removes the events from the core checkpoint.
  func absorbCoreEvents(_ events: [PigeonCoreEvent]) throws {
    guard !events.isEmpty else { return }
    var candidate = groupConversations
    for event in events {
      let groupID = groupID(for: event)
      var conversation = candidate[groupID] ?? GroupConversation(id: groupID)
      try GroupEventReducer.reduce(event, into: &conversation, localIdentity: myID)
      candidate[groupID] = conversation
    }
    if candidate != groupConversations {
      groupConversations = candidate
      guard persist() else { throw PlatformError.Unavailable }
    }
    try acknowledgeCoreEvents(events.map(\.id))
  }

  func consumeGroupRelayMessage(_ ciphertext: Data, requestID: String) -> Bool {
    guard isUnlocked, isPersistenceHealthy else { return false }
    do {
      try executeCore(
        PigeonCoreCommand(
          id: "group-message:\(requestID)",
          body: .applyInbound(
            PigeonApplyInbound(
              kind: .groupMessage,
              payload: ciphertext,
              requestID: requestID))))
      return true
    } catch {
      return false
    }
  }

  func consumePairwiseMessage(_ ciphertext: Data, requestID: String) -> Bool {
    guard isUnlocked, isPersistenceHealthy else { return false }
    do {
      try executeCore(
        PigeonCoreCommand(
          id: "pairwise-message:\(requestID)",
          body: .applyInbound(
            PigeonApplyInbound(
              kind: .pairwise,
              payload: ciphertext,
              requestID: requestID))))
      return true
    } catch {
      return false
    }
  }

  func consumeCoordinatorCandidate(
    _ receipt: PigeonCoordinatorReceipt,
    candidate: Data,
    requestID: String
  ) -> Bool {
    guard isUnlocked, isPersistenceHealthy else { return false }
    do {
      let inbound = try PigeonApplyInbound.coordinatorCandidate(
        receipt: receipt,
        candidate: candidate,
        requestID: requestID)
      try executeCore(
        PigeonCoreCommand(
          id: "group-coordinator:\(requestID)",
          body: .applyInbound(inbound)))
      return true
    } catch {
      return false
    }
  }

  func acknowledgeCoreOutbound(_ itemID: String) -> Bool {
    guard isUnlocked, isPersistenceHealthy else { return false }
    do {
      try executeCore(
        PigeonCoreCommand(
          id: "ack-outbound:\(itemID)",
          body: .acknowledgeEffects(
            PigeonAcknowledgeEffects(outboundItemIDs: [itemID]))))
      return true
    } catch {
      return false
    }
  }

  private func acknowledgeCoreEvents(_ eventIDs: [String]) throws {
    guard let coreClient else { throw PlatformError.Unavailable }
    let encodedIDs = try JSONEncoder().encode(eventIDs)
    let digest = SHA256.hash(data: encodedIDs)
      .map { String(format: "%02x", $0) }
      .joined()
    _ = try coreClient.execute(
      PigeonCoreCommand(
        id: "ack-events:\(digest)",
        body: .acknowledgeEffects(
          PigeonAcknowledgeEffects(eventIDs: eventIDs))))
    applyCoreSnapshot(try coreClient.stateSnapshot())
  }

  private func groupID(for event: PigeonCoreEvent) -> Data {
    switch event.body {
    case .groupCreated(let value): value.groupID
    case .groupMessageReceived(let value): value.groupID
    case .groupReactionReceived(let value): value.groupID
    case .groupPolicyChanged(let value): value.groupID
    case .groupDeliveryChanged(let value): value.groupID
    case .groupSecurityWarning(let value): value.groupID
    }
  }
}
