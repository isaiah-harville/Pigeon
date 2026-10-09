import CryptoKit
import Foundation

struct IdentityMoveAction {
  let retireSource: @MainActor () async throws -> Void
  let completeSource: @MainActor @Sendable () -> Void
}

/// Human-confirmed local move protocol. No archive bytes leave either phone
/// until both people confirm the same code on both screens.
@MainActor
@Observable
final class IdentityMoveCoordinator {
  enum Mode { case source, destination }
  enum Phase: Equatable {
    case discovering
    case compareCode(String)
    case transferring
    case staging
    case retiring
    case finished
    case failed(String)
  }

  private struct Packet: Codable {
    let kind: String
    var transferID: UUID?
    var bytes: Data?
  }

  private let mode: Mode
  private let transport: IdentityMoveTransport
  private let stage: IdentityMoveStage
  private let journal: IdentityMoveSourceJournal
  private let sourceSession: SessionManager?
  private let action: IdentityMoveAction
  private var transferID: UUID?
  private var channel: IdentityMoveChannel?
  private var localConfirmed = false
  private var peerConfirmed = false
  private var incoming = Data()
  private var sentDigest: Data?
  private var sentArchive: Data?
  private var isSending = false
  private(set) var phase: Phase = .discovering
  var peers: [String] { transport.discoveredPeerNames }
  var isConnected: Bool { transport.isConnected }

  init(mode: Mode, sourceSession: SessionManager?, action: IdentityMoveAction) throws {
    self.mode = mode
    self.transport = IdentityMoveTransport(
      role: mode == .source ? .source : .destination)
    self.stage = try IdentityMoveStage()
    self.journal = try IdentityMoveSourceJournal()
    self.sourceSession = sourceSession
    self.action = action
    transport.onConnected = { [weak self] in self?.connected() }
    transport.onDisconnected = { [weak self] in self?.disconnected() }
    transport.onData = { [weak self] data in self?.receive(data) }
  }

  convenience init(mode: Mode, action: IdentityMoveAction) throws {
    try self.init(mode: mode, sourceSession: nil, action: action)
  }

  func start() {
    if mode == .source {
      do { transferID = try journal.pendingTransferID() ?? UUID() } catch {
        fail("The previous move record cannot be read.")
        return
      }
    }
    transport.start()
  }

  func connect(to peer: String) { transport.connect(to: peer) }

  func confirmCode() {
    guard case .compareCode = phase, !localConfirmed else { return }
    do {
      localConfirmed = true
      try sendSecure(Packet(kind: "confirmed"))
      advanceAfterConfirmation()
    } catch { fail("Could not confirm the secure connection.") }
  }

  func stop() {
    transport.stop()
    guard mode == .source, phase != .retiring, phase != .finished,
      !CleanSlateRecovery().isPending, let sourceSession
    else { return }
    do {
      if journal.isPending {
        guard try journal.requiresSourceFreeze(identity: sourceSession.identity) else { return }
        try journal.cancelBeforeRetirement(identity: sourceSession.identity)
      }
      sourceSession.cancelIdentityMove()
    } catch {
      fail("The prepared move record could not be removed. Reopen Pigeon to recover.")
    }
  }

  func finish() {
    guard phase == .finished else { return }
    action.completeSource()
  }

  private func connected() {
    guard mode == .source, let transferID, channel == nil else { return }
    do {
      let channel = IdentityMoveChannel(role: .source, transferID: transferID)
      let key = channel.publicKey
      self.channel = channel
      try sendRaw(Packet(kind: "hello", transferID: transferID, bytes: key))
    } catch { fail("Could not start the secure connection.") }
  }

  private func disconnected() {
    guard phase != .finished else { return }
    if case .failed = phase { return }
    if phase == .retiring {
      fail("The old phone retired its identity. Reconnect both phones to finish activation.")
    } else if phase != .discovering {
      fail("The phones disconnected. Reopen the move on both phones.")
    }
  }

  private func receive(_ data: Data) {
    guard !data.isEmpty, data.count <= 70 * 1024 else {
      fail("Invalid move packet.")
      return
    }
    do {
      let packet: Packet
      if data.first == 0 {
        packet = try PropertyListDecoder().decode(Packet.self, from: Data(data.dropFirst()))
        try receiveHello(packet)
        return
      }
      guard data.first == 1, var channel else {
        throw IdentityMoveChannelError.invalidFrame
      }
      let plaintext = try channel.open(Data(data.dropFirst()))
      self.channel = channel
      packet = try PropertyListDecoder().decode(Packet.self, from: plaintext)
      try receiveSecure(packet)
    } catch {
      fail("The move channel rejected a packet. Restart the transfer.")
    }
  }

  private func receiveHello(_ packet: Packet) throws {
    guard packet.kind == "hello", let id = packet.transferID,
      let peerKey = packet.bytes, peerKey.count == 65,
      channel?.publicKey != peerKey
    else { throw IdentityMoveChannelError.invalidPeerKey }
    if mode == .destination {
      if let pending = try stage.pendingTransferID(), pending != id {
        throw IdentityMoveStage.StageError.invalidState
      }
      transferID = id
      var newChannel = IdentityMoveChannel(role: .destination, transferID: id)
      let ownKey = newChannel.publicKey
      let code = try newChannel.establish(peerPublicKey: peerKey)
      channel = newChannel
      try sendRaw(Packet(kind: "hello", transferID: id, bytes: ownKey))
      phase = .compareCode(code)
    } else {
      guard transferID == id, var channel else {
        throw IdentityMoveChannelError.invalidPeerKey
      }
      let code = try channel.establish(peerPublicKey: peerKey)
      self.channel = channel
      phase = .compareCode(code)
    }
  }

  private func advanceAfterConfirmation() {
    guard localConfirmed, peerConfirmed else { return }
    phase = .transferring
    if mode == .destination {
      do {
        if let transferID,
          let digest = try stage.stagedDigest(for: transferID)
        {
          try sendSecure(Packet(kind: "staged", bytes: digest))
        }
      } catch { fail("The staged transfer could not be resumed.") }
    } else {
      Task { await sendArchiveIfNeeded() }
    }
  }

  private func sendRaw(_ packet: Packet) throws {
    let encoder = PropertyListEncoder()
    encoder.outputFormat = .binary
    try transport.send(Data([0]) + encoder.encode(packet))
  }

  private func sendSecure(_ packet: Packet) throws {
    guard var channel else { throw IdentityMoveChannelError.unavailable }
    let encoder = PropertyListEncoder()
    encoder.outputFormat = .binary
    let frame = try channel.seal(encoder.encode(packet))
    self.channel = channel
    try transport.send(Data([1]) + frame)
  }

  private func fail(_ message: String) {
    phase = .failed(message)
    transport.stop()
    if mode == .source, !journal.isPending,
      sourceSession?.isIdentityMoveFrozen == true
    {
      sourceSession?.cancelIdentityMove()
    }
  }
}

extension IdentityMoveCoordinator {
  private func sendArchiveIfNeeded() async {
    guard !isSending else { return }
    isSending = true
    defer { isSending = false }
    do {
      if journal.isPending { return }
      guard let sourceSession, let transferID else {
        throw IdentityMoveStage.StageError.invalidState
      }
      let archive = try sourceSession.prepareIdentityMoveArchive(transferID: transferID)
      let bytes = try archive.encode()
      sentArchive = bytes
      let digest = Data(SHA256.hash(data: bytes))
      sentDigest = digest
      for offset in stride(from: 0, to: bytes.count, by: 60 * 1024) {
        let end = min(offset + 60 * 1024, bytes.count)
        try sendSecure(Packet(kind: "chunk", bytes: bytes.subdata(in: offset..<end)))
        await Task.yield()
      }
      try sendSecure(Packet(kind: "end", bytes: digest))
    } catch { fail("The old phone could not prepare the transfer archive.") }
  }

  private func receiveSecure(_ packet: Packet) throws {
    switch packet.kind {
    case "confirmed":
      guard case .compareCode = phase else { throw IdentityMoveChannelError.invalidFrame }
      peerConfirmed = true
      advanceAfterConfirmation()
    case "chunk": try receiveChunk(packet.bytes)
    case "end": try receiveArchiveEnd(packet.bytes)
    case "staged": try receiveStaged(packet.bytes)
    case "retired": try receiveRetired(packet.bytes)
    case "done":
      guard mode == .source, phase == .retiring else {
        throw IdentityMoveChannelError.invalidFrame
      }
      try journal.finish()
      phase = .finished
    default: throw IdentityMoveChannelError.invalidFrame
    }
  }

  private func receiveChunk(_ bytes: Data?) throws {
    guard mode == .destination, localConfirmed, peerConfirmed,
      let bytes, incoming.count + bytes.count <= IdentityMoveArchive.maximumEncodedBytes
    else { throw IdentityMoveChannelError.invalidFrame }
    incoming.append(bytes)
    phase = .transferring
  }

  private func receiveArchiveEnd(_ digest: Data?) throws {
    guard mode == .destination, localConfirmed, peerConfirmed, let digest,
      digest == Data(SHA256.hash(data: incoming)), let transferID
    else { throw IdentityMoveChannelError.invalidFrame }
    let archive = try IdentityMoveArchive.decode(incoming)
    guard archive.transferID == transferID else { throw IdentityMoveChannelError.invalidFrame }
    phase = .staging
    try stage.stage(archive, digest: digest)
    incoming.removeAll(keepingCapacity: false)
    try sendSecure(Packet(kind: "staged", bytes: digest))
  }

  private func receiveStaged(_ digest: Data?) throws {
    guard mode == .source, localConfirmed, peerConfirmed, let digest else {
      throw IdentityMoveChannelError.invalidFrame
    }
    if let receipt = try journal.receipt() {
      guard receipt.digest == digest else { throw IdentityMoveChannelError.invalidFrame }
      try sendSecure(Packet(kind: "retired", bytes: receipt.signature))
      phase = .retiring
      return
    }
    guard let transferID, let sourceSession else { throw IdentityMoveChannelError.invalidFrame }
    try prepareRetirement(digest: digest, sourceSession: sourceSession)
    phase = .retiring
    Task {
      do {
        try await action.retireSource()
        guard let receipt = try journal.receipt(),
          receipt.transferID == transferID, receipt.digest == digest
        else { throw IdentityMoveStage.StageError.invalidState }
        try sendSecure(Packet(kind: "retired", bytes: receipt.signature))
      } catch { fail("The old phone could not retire its identity. Reopen Pigeon to recover.") }
    }
  }

  private func prepareRetirement(digest: Data, sourceSession: SessionManager) throws {
    if let prepared = try journal.preparedDigest() {
      guard prepared == digest else { throw IdentityMoveChannelError.invalidFrame }
    } else {
      guard digest == sentDigest, let sentArchive else {
        throw IdentityMoveChannelError.invalidFrame
      }
      let archive = try IdentityMoveArchive.decode(sentArchive)
      try journal.prepare(
        archive: archive, digest: digest,
        identity: sourceSession.identity)
    }
  }

  private func receiveRetired(_ signature: Data?) throws {
    guard mode == .destination, localConfirmed, peerConfirmed, let transferID,
      let digest = try stage.stagedDigest(for: transferID), let signature
    else { throw IdentityMoveChannelError.invalidFrame }
    try stage.acceptRetirement(
      transferID: transferID,
      digest: digest, signature: signature)
    try stage.activate()
    try sendSecure(Packet(kind: "done"))
    phase = .finished
  }

}
