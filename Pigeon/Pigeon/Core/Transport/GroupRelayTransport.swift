import Foundation
import PigeonFFI

/// Maintains one authenticated opaque WebSocket per active group. All
/// cryptographic operations are delegated to `pigeon-core`; this layer only
/// moves typed ciphertext effects and advances a relay cursor after durable
/// core consumption.
@MainActor
final class GroupRelayTransport {
  private typealias Connection = GroupRelayConnection
  private typealias Effect = GroupRelayEffect
  private typealias Operation = GroupRelayOperation

  typealias ChallengeSigner = (_ groupID: Data, _ nonce: Data) throws -> Data
  typealias MessageConsumer = (_ ciphertext: Data, _ requestID: String) -> Bool
  typealias CoordinatorConsumer = (
    _ receipt: PigeonCoordinatorReceipt, _ candidate: Data, _ requestID: String
  ) -> Bool

  var onMessage: MessageConsumer?
  var onCoordinatorCandidate: CoordinatorConsumer?
  var onEffectDelivered: ((String) -> Bool)?
  var onAuthenticated: ((_ groupID: Data, _ capabilityID: Data) -> Bool)?

  private let signer: ChallengeSigner
  private let session: URLSession
  private var connections: [Data: Connection] = [:]

  convenience init(signer: @escaping ChallengeSigner) {
    self.init(session: .shared, signer: signer)
  }

  init(session: URLSession, signer: @escaping ChallengeSigner) {
    self.session = session
    self.signer = signer
  }

  func disconnect() {
    for connection in connections.values {
      stop(connection)
    }
    connections.removeAll()
  }

  func reconfigure(snapshot: PigeonCoreSnapshot) {
    let active = snapshot.groups.filter { group in
      !group.dissolved
        && group.capabilityPublicKey.count == 32
        && group.capabilityID.count == 32
        && Self.endpoint(for: URL(string: group.relayURL)) != nil
    }
    let pendingIDs = Set(
      snapshot.pendingOutbound.compactMap { item in
        (try? item.relayAction()).map { _ in item.destination }
      })
    let activeIDs = Set(active.map(\.coordinationID)).union(pendingIDs)
    for (id, connection) in connections where !activeIDs.contains(id) {
      stop(connection)
      connections[id] = nil
    }
    for group in active {
      let connection: Connection
      if let existing = connections[group.coordinationID], existing.usesSameEndpoint(as: group) {
        existing.group = group
        existing.authorization.requireConfirmation()
        connection = existing
      } else {
        if let existing = connections[group.coordinationID] { stop(existing) }
        connection = Connection(group: group)
        connections[group.coordinationID] = connection
        start(connection)
      }
    }
    reconcileEffects(snapshot.pendingOutbound, groups: snapshot.groups)
  }

}

extension GroupRelayTransport {
  private func reconcileEffects(
    _ pending: [PigeonCoreOutboundItem], groups: [PigeonGroupState]
  ) {
    let ids = Set(pending.map(\.id))
    for connection in connections.values {
      connection.queue.removeAll { operation in
        if case .effect(let effect) = operation { return !ids.contains(effect.id) }
        return false
      }
    }
    for item in pending {
      guard let action = try? item.relayAction() else { continue }
      if connections[item.destination] == nil,
        case .registration(let registration) = action,
        let source = groups.first(where: { group in
          registration.capabilities.contains { capability in
            capability.publicKey == group.capabilityPublicKey
          }
        }),
        let local = registration.capabilities.first(where: { capability in
          capability.publicKey == source.capabilityPublicKey
        })
      {
        let replacement = PigeonGroupState(
          groupID: source.groupID, ownerIdentity: source.ownerIdentity,
          adminIdentities: source.adminIdentities, memberIdentities: source.memberIdentities,
          name: source.name, relayURL: item.relayURL,
          coordinationID: registration.coordinationID, meshEnabled: source.meshEnabled,
          epoch: source.epoch + 1,
          policyRevision: registration.authorizationGeneration, dissolved: source.dissolved,
          capabilityPublicKey: source.capabilityPublicKey, capabilityID: local.capabilityID,
          coordinatorPublicKey: source.coordinatorPublicKey)
        let connection = Connection(group: replacement, confirmsAuthorization: false)
        connections[item.destination] = connection
        start(connection)
      }
      guard let connection = connections[item.destination], !contains(item.id, in: connection)
      else { continue }
      connection.queue.append(.effect(Effect(id: item.id, action: action)))
      sendNext(connection)
    }
  }

  private func start(_ connection: Connection) {
    connection.supervisor = Task { [weak self, weak connection] in
      guard let self, let connection else { return }
      var backoff = 1.0
      while !Task.isCancelled {
        do {
          try await self.serve(connection)
          backoff = 1
        } catch {
          guard !Task.isCancelled else { break }
          connection.ready = false
          if let awaiting = connection.awaiting {
            connection.queue.insert(awaiting, at: 0)
          }
          connection.awaiting = nil
          connection.socket?.cancel(with: .goingAway, reason: nil)
          try? await Task.sleep(for: .seconds(min(backoff, 30)))
          backoff = min(backoff * 2, 30)
        }
      }
    }
  }

  private func stop(_ connection: Connection) {
    connection.supervisor?.cancel()
    connection.socket?.cancel(with: .goingAway, reason: nil)
  }

  private func serve(_ connection: Connection) async throws {
    guard let url = Self.endpoint(for: URL(string: connection.group.relayURL)) else {
      throw RelayError.protocolError
    }
    let socket = session.webSocketTask(with: url)
    connection.socket = socket
    socket.resume()
    try await GroupRelaySocket.send(GroupRelayProtocol.hello(), over: socket)
    guard case .compatible(let version, _) = try await GroupRelaySocket.receive(over: socket),
      version == GroupRelayProtocol.version
    else { throw RelayError.incompatible }

    let registration = takeRegistration(from: connection)
    if let registration {
      connection.awaiting = .effect(registration)
      try await GroupRelaySocket.send(GroupRelayProtocol.action(registration.action), over: socket)
      guard case .registered = try await GroupRelaySocket.receive(over: socket) else {
        throw RelayError.handshake
      }
    }
    try await authenticate(connection, over: socket)
    connection.ready = true
    connection.fetchedAfterConnect = false
    if let registration {
      guard onEffectDelivered?(registration.id) == true else {
        throw RelayError.protocolError
      }
      connection.awaiting = nil
    }
    sendNext(connection)

    while !Task.isCancelled {
      try handle(try await GroupRelaySocket.receive(over: socket), for: connection)
    }
  }

  private func authenticate(
    _ connection: Connection,
    over socket: URLSessionWebSocketTask
  ) async throws {
    try await GroupRelaySocket.send(
      GroupRelayProtocol.authenticate(
        coordinationID: connection.group.coordinationID,
        capabilityID: connection.group.capabilityID),
      over: socket)
    guard case .challenge(let nonce) = try await GroupRelaySocket.receive(over: socket) else {
      throw RelayError.handshake
    }
    let signature = try signer(connection.group.groupID, nonce)
    try await GroupRelaySocket.send(GroupRelayProtocol.auth(signature: signature), over: socket)
    guard case .ok = try await GroupRelaySocket.receive(over: socket) else {
      throw RelayError.handshake
    }
    guard
      connection.authorization.confirmIfRequired({
        onAuthenticated?(connection.group.groupID, connection.group.capabilityID) == true
      })
    else {
      throw RelayError.protocolError
    }
  }

  private func handle(
    _ frame: GroupRelayProtocol.ServerFrame,
    for connection: Connection
  ) throws {
    switch frame {
    case .wake:
      connection.needsMessageFetch = true
    case .entries(let entries):
      guard connection.awaiting == .fetchMessages else { throw RelayError.protocolError }
      connection.awaiting = nil
      try consume(entries, for: connection)
    case .appended:
      try completeSimpleEffect(for: connection)
    case .ok:
      try completeOK(for: connection)
    case .coordinatorReceipt(let receipt):
      try completeSubmission(receipt, for: connection)
    case .coordinatorCandidates(let candidates):
      try completeCoordinatorFetch(candidates, for: connection)
    case .error:
      throw RelayError.protocolError
    case .compatible, .incompatible, .challenge, .registered, .coordinatorKey, .ignored:
      break
    }
    sendNext(connection)
  }
}

extension GroupRelayTransport {
  private func consume(_ entries: [GroupRelayProtocol.Entry], for connection: Connection) throws {
    var lastSequence: UInt64?
    for entry in entries {
      let requestID = "relay-group-\(connection.group.coordinationID.hexEncoded)-\(entry.sequence)"
      guard onMessage?(entry.ciphertext, requestID) == true else { throw RelayError.protocolError }
      lastSequence = entry.sequence
    }
    if let lastSequence { connection.queue.insert(.advance(lastSequence), at: 0) }
  }

  private func completeSimpleEffect(for connection: Connection) throws {
    guard case .effect(let effect)? = connection.awaiting,
      case .append = effect.action
    else { throw RelayError.protocolError }
    connection.awaiting = nil
    guard onEffectDelivered?(effect.id) == true else {
      connection.awaiting = .effect(effect)
      throw RelayError.protocolError
    }
  }

  private func completeOK(for connection: Connection) throws {
    guard let awaiting = connection.awaiting else { throw RelayError.protocolError }
    switch awaiting {
    case .effect(let effect):
      guard case .control = effect.action else { throw RelayError.protocolError }
    case .advance:
      break
    case .fetchMessages, .fetchCoordinator:
      throw RelayError.protocolError
    }
    connection.awaiting = nil
    if case .effect(let effect) = awaiting,
      onEffectDelivered?(effect.id) != true
    {
      connection.awaiting = awaiting
      throw RelayError.protocolError
    }
  }

  private func completeSubmission(
    _ receipt: GroupRelayProtocol.CoordinatorReceipt,
    for connection: Connection
  ) throws {
    guard case .effect(let effect)? = connection.awaiting,
      case .coordinatorSubmission(let submission) = effect.action
    else { throw RelayError.protocolError }
    let accepted =
      onCoordinatorCandidate?(
        receipt.publicValue, submission.candidate, "\(effect.id):receipt") == true
    guard accepted else { throw RelayError.protocolError }
    guard
      connection.authorization.confirmIfRequired({
        onAuthenticated?(connection.group.groupID, connection.group.capabilityID) == true
      })
    else {
      throw RelayError.protocolError
    }
    connection.awaiting = nil
    guard onEffectDelivered?(effect.id) == true else {
      connection.awaiting = .effect(effect)
      throw RelayError.protocolError
    }
  }

  private func completeCoordinatorFetch(
    _ candidates: [GroupRelayProtocol.CoordinatorCandidate],
    for connection: Connection
  ) throws {
    guard case .fetchCoordinator? = connection.awaiting else { throw RelayError.protocolError }
    for value in candidates {
      let requestID =
        "relay-coordinator-"
        + "\(value.receipt.coordinationID.hexEncoded)-\(value.receipt.sequence)"
      guard onCoordinatorCandidate?(value.receipt.publicValue, value.candidate, requestID) == true
      else { throw RelayError.protocolError }
    }
    connection.awaiting = nil
  }
}

extension GroupRelayTransport {
  private func sendNext(_ connection: Connection) {
    guard connection.ready,
      connection.awaiting == nil,
      let socket = connection.socket
    else { return }
    if connection.queue.isEmpty, !connection.fetchedAfterConnect {
      connection.fetchedAfterConnect = true
      connection.queue.append(.fetchMessages)
      connection.queue.append(.fetchCoordinator(connection.group.epoch))
    } else if connection.queue.isEmpty, connection.needsMessageFetch {
      connection.needsMessageFetch = false
      connection.queue.append(.fetchMessages)
    }
    guard !connection.queue.isEmpty else { return }
    let operation = connection.queue.removeFirst()
    connection.awaiting = operation
    Task { [weak self, weak connection] in
      do {
        guard let self else { return }
        let data = try self.data(for: operation)
        try await GroupRelaySocket.send(data, over: socket)
      } catch {
        connection?.socket?.cancel(with: .internalServerError, reason: nil)
      }
    }
  }

  private func data(for operation: Operation) throws -> Data {
    switch operation {
    case .effect(let effect): return try GroupRelayProtocol.action(effect.action)
    case .fetchMessages: return try GroupRelayProtocol.fetch(after: 0)
    case .advance(let sequence): return try GroupRelayProtocol.advance(to: sequence)
    case .fetchCoordinator(let sequence):
      return try GroupRelayProtocol.coordinatorFetch(after: sequence)
    }
  }

  private func takeRegistration(from connection: Connection) -> Effect? {
    guard
      let index = connection.queue.firstIndex(where: { operation in
        if case .effect(let effect) = operation, case .registration = effect.action {
          return true
        }
        return false
      }), case .effect(let effect) = connection.queue.remove(at: index)
    else { return nil }
    return effect
  }

  private func contains(_ id: String, in connection: Connection) -> Bool {
    if case .effect(let effect)? = connection.awaiting, effect.id == id { return true }
    return connection.queue.contains { operation in
      if case .effect(let effect) = operation { return effect.id == id }
      return false
    }
  }

}
