import CryptoKit
import Darwin
import Foundation

/// Public, signed receipt retained until the receiving phone confirms activation.
/// Its old identity key signature can be replayed only for this transfer digest.
struct IdentityMoveSourceJournal {
  private struct Record: Codable {
    let transferID: UUID
    let digest: Data
    let oldPublicKey: Data
    let signature: Data
  }

  private let url: URL

  init() throws {
    let base = try FileManager.default.url(
      for: .applicationSupportDirectory,
      in: .userDomainMask, appropriateFor: nil, create: true)
    self.init(url: base.appendingPathComponent("pigeon.identity-move.source"))
  }

  init(url: URL) { self.url = url }

  var isPending: Bool { FileManager.default.fileExists(atPath: url.path) }

  /// A prepared source must not advance its checkpoint after a relaunch.
  func requiresSourceFreeze(identity: IdentityManager) throws -> Bool {
    guard isPending else { return false }
    let record = try PropertyListDecoder().decode(
      Record.self,
      from: Data(contentsOf: url))
    guard
      let oldKey = try? Curve25519.Signing.PublicKey(
        rawRepresentation: record.oldPublicKey),
      oldKey.isValidSignature(
        record.signature,
        for: IdentityMoveStage.retirementMessage(
          transferID: record.transferID, digest: record.digest))
    else { throw IdentityMoveStage.StageError.invalidReceipt }
    return identity.publicKey.rawRepresentation == record.oldPublicKey
  }

  func prepare(
    archive: IdentityMoveArchive, digest: Data,
    identity: IdentityManager
  ) throws {
    guard !isPending, digest.count == SHA256.byteCount else {
      throw IdentityMoveStage.StageError.invalidState
    }
    let message = IdentityMoveStage.retirementMessage(
      transferID: archive.transferID, digest: digest)
    let record = Record(
      transferID: archive.transferID, digest: digest,
      oldPublicKey: identity.publicKey.rawRepresentation,
      signature: try identity.sign(message))
    try PropertyListEncoder().encode(record).write(
      to: url,
      options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    let handle = try FileHandle(forWritingTo: url)
    try handle.synchronize()
    try handle.close()
    let directory = open(url.deletingLastPathComponent().path, O_RDONLY)
    guard directory >= 0 else { throw IdentityMoveStage.StageError.storageFailed }
    defer { close(directory) }
    guard fsync(directory) == 0 else {
      throw IdentityMoveStage.StageError.storageFailed
    }
  }

  func receipt() throws -> (transferID: UUID, digest: Data, signature: Data)? {
    guard isPending else { return nil }
    let record = try PropertyListDecoder().decode(
      Record.self,
      from: Data(contentsOf: url))
    guard
      let oldKey = try? Curve25519.Signing.PublicKey(
        rawRepresentation: record.oldPublicKey),
      oldKey.isValidSignature(
        record.signature,
        for: IdentityMoveStage.retirementMessage(
          transferID: record.transferID, digest: record.digest))
    else { throw IdentityMoveStage.StageError.invalidReceipt }
    let identity = try IdentityManager(creationPolicy: .existingOnly)
    guard identity.publicKey.rawRepresentation != record.oldPublicKey,
      !CleanSlateRecovery().isPending
    else { return nil }
    return (record.transferID, record.digest, record.signature)
  }

  func pendingTransferID() throws -> UUID? {
    guard isPending else { return nil }
    return try PropertyListDecoder().decode(
      Record.self,
      from: Data(contentsOf: url)
    ).transferID
  }

  func preparedDigest() throws -> Data? {
    guard isPending else { return nil }
    return try PropertyListDecoder().decode(
      Record.self,
      from: Data(contentsOf: url)
    ).digest
  }

  func cancelBeforeRetirement(identity: IdentityManager) throws {
    guard isPending else { return }
    let record = try PropertyListDecoder().decode(
      Record.self,
      from: Data(contentsOf: url))
    guard identity.publicKey.rawRepresentation == record.oldPublicKey else {
      throw IdentityMoveStage.StageError.invalidState
    }
    try FileManager.default.removeItem(at: url)
  }

  func finish() throws {
    guard try receipt() != nil else { throw IdentityMoveStage.StageError.invalidState }
    try FileManager.default.removeItem(at: url)
  }
}
